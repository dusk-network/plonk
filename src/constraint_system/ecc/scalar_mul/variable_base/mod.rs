use crate::constraint_system::ecc::{Point, PointScalar};
use crate::constraint_system::{variable::Variable, TurboComposer};
use dusk_bls12_381::Scalar;

/// Computes a Scalar multiplication with the input scalar and a chosen generator
pub fn variable_base_scalar_mul(
    composer: &mut TurboComposer,
    jubjub_var: Variable,
    point: Point,
) -> PointScalar {
    // Turn scalar into bits
    let raw_bls_scalar = *composer.variables.get(&jubjub_var).unwrap();
    let scalar_bits_var = scalar_decomposition(composer, jubjub_var, raw_bls_scalar);

    let identity = Point::identity(composer);
    let mut result = identity;

    for bit in scalar_bits_var.into_iter().rev() {
        result = result.fast_add(composer, result);
        let point_to_add = conditional_select_identity(composer, bit, point);
        result = result.fast_add(composer, point_to_add);
    }

    PointScalar {
        point: result,
        scalar: jubjub_var,
    }
}

/// If bit == 0, then return zero else return value
/// This is the polynomial f(x) = x * a
/// Where x is the bit
fn conditional_select_zero(
    composer: &mut TurboComposer,
    bit: Variable,
    value: Variable,
) -> Variable {
    // returns bit * value
    composer.mul(Scalar::one(), bit, value, Scalar::zero(), Scalar::zero())
}
/// If bit == 0, then return 1 else return value
/// This is the polynomial f(x) = 1 - x + xa
/// Where x is the bit
fn conditional_select_one(
    composer: &mut TurboComposer,
    bit: Variable,
    value: Variable,
) -> Variable {
    let value_scalar = composer.variables.get(&value).unwrap();
    let bit_scalar = composer.variables.get(&bit).unwrap();

    let f_x_scalar = Scalar::one() - bit_scalar + (bit_scalar * value_scalar);
    let f_x = composer.add_input(f_x_scalar);

    composer.poly_gate(
        bit,
        value,
        f_x,
        Scalar::one(),
        -Scalar::one(),
        Scalar::zero(),
        -Scalar::one(),
        Scalar::one(),
        Scalar::zero(),
    );

    f_x
}

// If bit == 0 choose identity, if bit == 1 choose point_b
fn conditional_select_identity(
    composer: &mut TurboComposer,
    bit: Variable,
    point_b: Point,
) -> Point {
    let x = conditional_select_zero(composer, bit, *point_b.x());
    let y = conditional_select_one(composer, bit, *point_b.y());

    Point { x, y }
}

fn scalar_decomposition(
    composer: &mut TurboComposer,
    witness_var: Variable,
    witness_scalar: Scalar,
) -> Vec<Variable> {
    // Decompose the bits
    let scalar_bits = scalar_to_bits(&witness_scalar);

    // Add all the bits into the composer
    let scalar_bits_var: Vec<Variable> = scalar_bits
        .iter()
        .map(|bit| composer.add_input(Scalar::from(*bit as u64)))
        .collect();

    // Take the first 252 bits
    let scalar_bits_var = scalar_bits_var[0..252].to_vec();

    // Now ensure that the bits correctly accumulate to the witness given
    let mut accumulator_var = composer.zero_var;
    let mut accumulator_scalar = Scalar::zero();

    for (power, bit) in scalar_bits_var.iter().enumerate() {
        composer.boolean_gate(*bit);

        let two_pow = Scalar::from(2).pow(&[power as u64, 0, 0, 0]);

        let q_l_a = (two_pow, *bit);
        let q_r_b = (Scalar::one(), accumulator_var);
        let q_c = Scalar::zero();
        let pi = Scalar::zero();

        accumulator_var = composer.add(q_l_a, q_r_b, q_c, pi);

        accumulator_scalar += two_pow * Scalar::from(scalar_bits[power] as u64);
    }
    composer.assert_equal(accumulator_var, witness_var);

    scalar_bits_var
}

fn scalar_to_bits(scalar: &Scalar) -> [u8; 256] {
    let mut res = [0u8; 256];
    let bytes = scalar.to_bytes();
    for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
        bits.iter_mut()
            .enumerate()
            .for_each(|(i, bit)| *bit = (byte >> i) & 1)
    }
    res
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::helper::*;
    use dusk_bls12_381::Scalar as BlsScalar;
    use dusk_jubjub::GENERATOR;
    use dusk_jubjub::{AffinePoint, ExtendedPoint, Fr as JubJubScalar};
    #[test]
    fn test_var_base_scalar_mul() {
        let res = gadget_tester(
            |composer| {
                let scalar = JubJubScalar::from_bytes_wide(&[
                    182, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166, 0,
                    59, 52, 1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,
                ]);
                let bls_scalar = BlsScalar::from_bytes(&scalar.to_bytes()).unwrap();
                let secret_scalar = composer.add_input(bls_scalar);

                let expected_point: AffinePoint = (ExtendedPoint::from(GENERATOR) * scalar).into();

                let point = Point::from_private_affine(composer, GENERATOR);

                let point_scalar = variable_base_scalar_mul(composer, secret_scalar, point);

                composer.assert_equal_public_point(point_scalar.into(), expected_point);
            },
            4096,
        );
        assert!(res.is_ok());
    }
}
