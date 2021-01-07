// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::ecc::Point;
use crate::constraint_system::StandardComposer;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubExtended};

impl Point {
    /// Adds two curve points together using a curve addition gate
    /// Note that since the points are not fixed the generator is not a part of the
    /// circuit description, however it is less efficient for a program width of 4.
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

        let p1 = JubJubAffine::from_raw_unchecked(*x_1_scalar, *y_1_scalar);
        let p2 = JubJubAffine::from_raw_unchecked(*x_2_scalar, *y_2_scalar);

        let point: JubJubAffine = (JubJubExtended::from(p1) + p2).into();
        let x_3_scalar = point.get_x();
        let y_3_scalar = point.get_y();

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
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_r
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_c
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_o
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_m
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_4
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_arith
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_range
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_logic
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_fixed_group_add
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);
        composer
            .q_lookup
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);

        composer.q_variable_group_add.push(BlsScalar::one());
        composer.q_variable_group_add.push(BlsScalar::zero());

        composer
            .public_inputs
            .append(&mut vec![BlsScalar::zero(), BlsScalar::zero()]);

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

#[cfg(test)]
mod test {
    use super::*;
    use crate::constraint_system::helper::*;
    use dusk_jubjub::GENERATOR;
    use dusk_jubjub::{JubJubAffine, JubJubExtended};
    #[test]
    fn test_curve_addition() {
        let res = gadget_tester(
            |composer| {
                let expected_point: JubJubAffine =
                    (JubJubExtended::from(GENERATOR) + JubJubExtended::from(GENERATOR)).into();
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
