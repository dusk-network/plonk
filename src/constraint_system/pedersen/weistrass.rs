use jubjub::Fq;
use jubjub::{AffinePoint, ExtendedPoint};
use std::ops::Add;
// Edwards Parameters
#[allow(dead_code, non_snake_case)]
fn edwards_d() -> Fq {
    let num = Fq::from(10240);
    let den = Fq::from(10241);
    -(num * den.invert().unwrap())
}
#[allow(dead_code, non_snake_case)]
fn edwards_a() -> Fq {
    -Fq::one()
}

// Montgomery Parameters
fn montgomery_a() -> Fq {
    Fq::from(40962)
}
fn montgomery_b() -> Fq {
    Fq::from_bytes(&[
        253, 95, 255, 255, 254, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9,
        8, 216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115,
    ])
    .unwrap()
}

// XXX: Montgomery scaling factor, however probably won't need as Montgomery is just an intermediate map
#[allow(dead_code, non_snake_case)]
fn scale_montgomery_b() -> Fq {
    montgomery_b().invert().unwrap().sqrt().unwrap()
}
#[allow(dead_code, non_snake_case)]
fn weierstrass_a() -> Fq {
    Fq::from_bytes(&[
        66, 9, 194, 212, 220, 52, 13, 197, 52, 147, 99, 94, 116, 94, 83, 32, 40, 35, 138, 55, 160,
        32, 98, 151, 232, 102, 114, 110, 207, 138, 158, 115,
    ])
    .unwrap()
}
#[allow(dead_code, non_snake_case)]
fn weierstrass_b() -> Fq {
    Fq::from_bytes(&[
        225, 40, 102, 76, 59, 195, 32, 113, 172, 102, 131, 255, 131, 20, 245, 187, 176, 20, 86,
        181, 1, 0, 198, 244, 103, 118, 102, 63, 60, 202, 229, 106,
    ])
    .unwrap()
}

// Edwards to Montgomery
#[allow(dead_code, non_snake_case)]
fn montgomery_parameters() -> (Fq, Fq) {
    let num = edwards_a() + edwards_d();
    let den = edwards_a() - edwards_d();
    let A = Fq::from(2) * (num * den.invert().unwrap());

    let num = Fq::from(4);
    let den = edwards_a() - edwards_d();
    let B = num * den.invert().unwrap();
    (A, B)
}
// Montgomery to Weierstrass
#[allow(dead_code, non_snake_case)]
fn weierstrass_parameters() -> (Fq, Fq) {
    let two = Fq::from(2);
    let three = Fq::from(3);
    let nine = Fq::from(9);
    let twenty_seven = Fq::from(27);

    let A_sq = montgomery_a().square();

    let B_sq = montgomery_b().square();
    let three_B_sq = three * montgomery_b().square();

    let B_cu = montgomery_b().square() * montgomery_b();

    let a = B_sq.invert().unwrap() - (A_sq * (three_B_sq).invert().unwrap());

    let b = montgomery_a() * (two * A_sq - nine) * ((twenty_seven * B_cu).invert().unwrap());

    (a, b)
}

#[allow(dead_code, non_snake_case)]
fn edwards_to_montgomery(point: AffinePoint) -> (Fq, Fq) {
    let x = point.get_x();
    let y = point.get_y();
    let one = Fq::one();

    let one_minus_y = one - y;
    let one_plus_y = one + y;

    let u = one_plus_y * one_minus_y.invert().unwrap();
    let v = one_plus_y * (one_minus_y * x).invert().unwrap();

    (u, v)
}
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Weierstrass {
    x: Fq,
    y: Fq,
}

impl From<AffinePoint> for Weierstrass {
    fn from(edwards: AffinePoint) -> Weierstrass {
        let (u, v) = edwards_to_montgomery(edwards);
        montgomery_to_weierstrass(u, v)
    }
}
impl From<ExtendedPoint> for Weierstrass {
    fn from(edwards: ExtendedPoint) -> Weierstrass {
        let affine_edwards: AffinePoint = edwards.into();
        let (u, v) = edwards_to_montgomery(affine_edwards);
        montgomery_to_weierstrass(u, v)
    }
}

#[allow(dead_code, non_snake_case)]
pub fn montgomery_to_weierstrass(u: Fq, v: Fq) -> Weierstrass {
    let inv_three = Fq::from(3).invert().unwrap();
    let inv_B = montgomery_b().invert().unwrap();

    let num_x = u + (montgomery_a() * inv_three);
    let x = num_x * inv_B;

    let y = v * inv_B;

    Weierstrass { x, y }
}

impl Weierstrass {
    #[allow(dead_code, non_snake_case)]
    fn double(&self) -> Self {
        let x1 = self.x;
        let y1 = self.y;

        let x1_sq = x1.square();

        let two = Fq::from(2);
        let three = Fq::from(3);

        let k = (three * x1_sq + weierstrass_a()) * (two * y1).invert().unwrap();

        let x3 = k.square() - two * x1;

        let y3 = k * (x1 - x3) - y1;

        Weierstrass { x: x3, y: y3 }
    }
}

impl Add<Weierstrass> for Weierstrass {
    type Output = Weierstrass;
    fn add(self, rhs: Weierstrass) -> Self::Output {
        let x1 = self.x;
        let y1 = self.y;
        let x2 = rhs.x;
        let y2 = rhs.y;

        let k = (y2 - y1) * (x2 - x1).invert().unwrap();

        let x3 = k.square() - x1 - x2;

        let y3 = k * (x1 - x3) - y1;

        Weierstrass { x: x3, y: y3 }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use jubjub::GENERATOR;
    #[test]
    fn test_mont_params() {
        let (got_a, got_b) = montgomery_parameters();

        assert_eq!(got_a, montgomery_a());
        assert_eq!(got_b, montgomery_b());
    }
    #[test]
    fn test_weistrass_params() {
        let (got_a, got_b) = weierstrass_parameters();
        assert_eq!(got_a, weierstrass_a());
        assert_eq!(got_b, weierstrass_b());
    }

    #[test]
    fn test_map_double_add() {
        let edwards_gen = ExtendedPoint::from(GENERATOR);
        let edwards_double_gen = edwards_gen.double();
        let edwards_triple_gen = edwards_double_gen + edwards_gen;

        // Compute expected Weierstrass points with the map
        let expected_weierstrass_double_gen = Weierstrass::from(edwards_double_gen);
        let expected_weierstrass_triple_gen = Weierstrass::from(edwards_triple_gen);

        // Compute double and triple gen on the Weierstrass Curve
        let weierstrass_gen = Weierstrass::from(edwards_gen);
        let weierstrass_double_gen = weierstrass_gen.double();
        let weierstrass_triple_gen = weierstrass_double_gen + weierstrass_gen;

        assert_eq!(weierstrass_double_gen, expected_weierstrass_double_gen);
        assert_eq!(weierstrass_triple_gen, expected_weierstrass_triple_gen);
    }
}
