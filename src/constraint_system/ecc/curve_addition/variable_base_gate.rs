// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::ecc::Point;
use crate::constraint_system::StandardComposer;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubExtended};

impl StandardComposer {
    /// Adds two curve points together using a curve addition gate
    /// Note that since the points are not fixed the generator is not a part of
    /// the circuit description, however it is less efficient for a program
    /// width of 4.
    pub fn point_addition_gate(
        &mut self,
        point_a: Point,
        point_b: Point,
    ) -> Point {
        // In order to verify that two points were correctly added
        // without going over a degree 4 polynomial, we will need
        // x_1, y_1, x_2, y_2
        // x_3, y_3,      x_1 * y_2

        let x_1 = point_a.x;
        let y_1 = point_a.y;
        let x_2 = point_b.x;
        let y_2 = point_b.y;

        // Compute the resulting point
        let x_1_scalar = self.variables.get(&x_1).unwrap();
        let y_1_scalar = self.variables.get(&y_1).unwrap();
        let x_2_scalar = self.variables.get(&x_2).unwrap();
        let y_2_scalar = self.variables.get(&y_2).unwrap();

        let p1 = JubJubAffine::from_raw_unchecked(*x_1_scalar, *y_1_scalar);
        let p2 = JubJubAffine::from_raw_unchecked(*x_2_scalar, *y_2_scalar);

        let point: JubJubAffine = (JubJubExtended::from(p1) + p2).into();
        let x_3_scalar = point.get_x();
        let y_3_scalar = point.get_y();

        let x1_scalar_y2_scalar = x_1_scalar * y_2_scalar;

        // Add the rest of the prepared points into the composer
        let x_1_y_2 = self.add_input(x1_scalar_y2_scalar);
        let x_3 = self.add_input(x_3_scalar);
        let y_3 = self.add_input(y_3_scalar);

        self.w_l.extend(&[x_1, x_3]);
        self.w_r.extend(&[y_1, y_3]);
        self.w_o.extend(&[x_2, self.zero_var]);
        self.w_4.extend(&[y_2, x_1_y_2]);
        let zeros = [BlsScalar::zero(), BlsScalar::zero()];

        self.q_l.extend(&zeros);
        self.q_r.extend(&zeros);
        self.q_c.extend(&zeros);
        self.q_o.extend(&zeros);
        self.q_m.extend(&zeros);
        self.q_4.extend(&zeros);
        self.q_arith.extend(&zeros);
        self.q_range.extend(&zeros);
        self.q_logic.extend(&zeros);
        self.q_fixed_group_add.extend(&zeros);
        self.q_lookup.extend(&zeros);

        self.q_variable_group_add.push(BlsScalar::one());
        self.q_variable_group_add.push(BlsScalar::zero());

        self.perm.add_variables_to_map(x_1, y_1, x_2, y_2, self.n);
        self.n += 1;

        self.perm.add_variables_to_map(
            x_3,
            y_3,
            self.zero_var,
            x_1_y_2,
            self.n,
        );
        self.n += 1;

        Point { x: x_3, y: y_3 }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::constraint_system::helper::*;
    use dusk_jubjub::GENERATOR;
    use dusk_jubjub::{JubJubAffine, JubJubExtended, EDWARDS_D};

    /// Adds two curve points together using the classical point addition
    /// algorithm. This method is slower than WNaf and is just meant to be the
    /// source of truth to test the WNaf method.
    pub fn classical_point_addition(
        composer: &mut StandardComposer,
        point_a: Point,
        point_b: Point,
    ) -> Point {
        let x1 = point_a.x;
        let y1 = point_a.y;

        let x2 = point_b.x;
        let y2 = point_b.y;

        // x1 * y2
        let x1_y2 =
            composer.mul(BlsScalar::one(), x1, y2, BlsScalar::zero(), None);
        // y1 * x2
        let y1_x2 =
            composer.mul(BlsScalar::one(), y1, x2, BlsScalar::zero(), None);
        // y1 * y2
        let y1_y2 =
            composer.mul(BlsScalar::one(), y1, y2, BlsScalar::zero(), None);
        // x1 * x2
        let x1_x2 =
            composer.mul(BlsScalar::one(), x1, x2, BlsScalar::zero(), None);
        // d x1x2 * y1y2
        let d_x1_x2_y1_y2 =
            composer.mul(EDWARDS_D, x1_x2, y1_y2, BlsScalar::zero(), None);

        // x1y2 + y1x2
        let x_numerator = composer.add(
            (BlsScalar::one(), x1_y2),
            (BlsScalar::one(), y1_x2),
            BlsScalar::zero(),
            None,
        );

        // y1y2 - a * x1x2 (a=-1) => y1y2 + x1x2
        let y_numerator = composer.add(
            (BlsScalar::one(), y1_y2),
            (BlsScalar::one(), x1_x2),
            BlsScalar::zero(),
            None,
        );

        // 1 + dx1x2y1y2
        let x_denominator = composer.add(
            (BlsScalar::one(), d_x1_x2_y1_y2),
            (BlsScalar::zero(), composer.zero_var),
            BlsScalar::one(),
            None,
        );

        // Compute the inverse
        let inv_x_denom = composer
            .variables
            .get(&x_denominator)
            .unwrap()
            .invert()
            .unwrap();
        let inv_x_denom = composer.add_input(inv_x_denom);

        // Assert that we actually have the inverse
        // inv_x * x = 1
        composer.mul_gate(
            x_denominator,
            inv_x_denom,
            composer.zero_var,
            BlsScalar::one(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            None,
        );

        // 1 - dx1x2y1y2
        let y_denominator = composer.add(
            (-BlsScalar::one(), d_x1_x2_y1_y2),
            (BlsScalar::zero(), composer.zero_var),
            BlsScalar::one(),
            None,
        );
        let inv_y_denom = composer
            .variables
            .get(&y_denominator)
            .unwrap()
            .invert()
            .unwrap();
        let inv_y_denom = composer.add_input(inv_y_denom);
        // Assert that we actually have the inverse
        // inv_y * y = 1
        composer.mul_gate(
            y_denominator,
            inv_y_denom,
            composer.zero_var,
            BlsScalar::one(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            None,
        );

        // We can now use the inverses

        let x_3 = composer.mul(
            BlsScalar::one(),
            inv_x_denom,
            x_numerator,
            BlsScalar::zero(),
            None,
        );
        let y_3 = composer.mul(
            BlsScalar::one(),
            inv_y_denom,
            y_numerator,
            BlsScalar::zero(),
            None,
        );

        Point { x: x_3, y: y_3 }
    }

    #[test]
    fn test_curve_addition() {
        let res = gadget_tester(
            |composer| {
                let expected_point: JubJubAffine =
                    (JubJubExtended::from(GENERATOR)
                        + JubJubExtended::from(GENERATOR))
                    .into();
                let x = composer.add_input(GENERATOR.get_x());
                let y = composer.add_input(GENERATOR.get_y());
                let point_a = Point { x, y };
                let point_b = Point { x, y };

                let point = composer.point_addition_gate(point_a, point_b);
                let point2 =
                    classical_point_addition(composer, point_a, point_b);

                composer.assert_equal_point(point, point2);

                composer
                    .assert_equal_public_point(point.into(), expected_point);
            },
            2000,
        );
        assert!(res.is_ok());
    }
}
