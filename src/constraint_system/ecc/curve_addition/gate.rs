use crate::constraint_system::ecc::Point;
use crate::constraint_system::StandardComposer;
use dusk_bls12_381::Scalar;

impl Point {
    /// Adds two curve points together using the curve addition gate
    pub fn fast_add(&self, composer: &mut StandardComposer, point_b: Point) -> Point {
        // In order to verify that two points were correctly added
        // without going over a degree 4 polynomial, we will need
        // x_1, y_1, x_2, y_2
        // x_3, y_3,      x_1 * y_2

        let x_1 = self.x;
        let y_1 = self.y;
        let x_2 = point_b.x;
        let y_2 = point_b.y;

        // Compute the resulting point
        let x_1_scalar = composer.variables.get(&x_1).unwrap();
        let y_1_scalar = composer.variables.get(&y_1).unwrap();
        let x_2_scalar = composer.variables.get(&x_2).unwrap();
        let y_2_scalar = composer.variables.get(&y_2).unwrap();

        let (x_3_scalar, y_3_scalar) =
            compute_x_3(*x_1_scalar, *y_1_scalar, *x_2_scalar, *y_2_scalar);

        let x1_scalar_y2_scalar = x_1_scalar * y_2_scalar;

        // Add the rest of the prepared points into the composer
        let x_1_y_2 = composer.add_input(x1_scalar_y2_scalar);
        let x_3 = composer.add_input(x_3_scalar);
        let y_3 = composer.add_input(y_3_scalar);

        composer.w_l.append(&mut vec![x_1, x_3]);
        composer.w_r.append(&mut vec![y_1, y_3]);
        composer.w_o.append(&mut vec![x_2, composer.zero_var]);
        composer.w_4.append(&mut vec![y_2, x_1_y_2]);

        composer
            .q_l
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_r
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_c
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_o
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_m
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_4
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_arith
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_range
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_logic
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);
        composer
            .q_fixed_base
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);

        composer.q_curve_add.push(Scalar::one());
        composer.q_curve_add.push(Scalar::zero());

        composer
            .public_inputs
            .append(&mut vec![Scalar::zero(), Scalar::zero()]);

        composer
            .perm
            .add_variables_to_map(x_1, y_1, x_2, y_2, composer.n);
        composer.n += 1;

        composer
            .perm
            .add_variables_to_map(x_3, y_3, composer.zero_var, x_1_y_2, composer.n);
        composer.n += 1;

        Point { x: x_3, y: y_3 }
    }
}

// XXX: JubJub does not allow us to create a point from X and Y
// So we do curve addition manually here
fn compute_x_3(x_1: Scalar, y_1: Scalar, x_2: Scalar, y_2: Scalar) -> (Scalar, Scalar) {
    use dusk_jubjub::EDWARDS_D;

    let x1_y2 = x_1 * y_2;
    let x2_y1 = x_2 * y_1;
    let x1_x2 = x_1 * x_2;
    let y1_y2 = y_1 * y_2;

    let k = EDWARDS_D * x1_y2 * x2_y1;

    let x3_num = x1_y2 + x2_y1;
    let x3_den = (Scalar::one() + k).invert().unwrap_or(Scalar::zero());
    let x3 = x3_num * x3_den;

    let y3_num = y1_y2 + x1_x2;
    let y3_den = (Scalar::one() - k).invert().unwrap_or(Scalar::zero());
    let y3 = y3_num * y3_den;

    (x3, y3)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constraint_system::helper::*;
    use dusk_jubjub::GENERATOR;
    use dusk_jubjub::{AffinePoint, ExtendedPoint};
    #[test]
    fn test_curve_addition() {
        let res = gadget_tester(
            |composer| {
                let expected_point: AffinePoint =
                    (ExtendedPoint::from(GENERATOR) + ExtendedPoint::from(GENERATOR)).into();
                let x = composer.add_input(GENERATOR.get_x());
                let y = composer.add_input(GENERATOR.get_y());
                let point_a = Point { x, y };
                let point_b = Point { x, y };

                let point = point_a.fast_add(composer, point_b);
                let point2 = point_a.slow_add(composer, point_b);

                composer.assert_equal_point(point, point2);

                composer.assert_equal_public_point(point.into(), expected_point);
            },
            2000,
        );
        assert!(res.is_ok());
    }
}
