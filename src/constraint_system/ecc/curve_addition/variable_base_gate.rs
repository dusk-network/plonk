// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::ecc::WitnessPoint;
use crate::constraint_system::TurboComposer;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubExtended};

impl TurboComposer {
    /// Adds two curve points together using a curve addition gate
    /// Note that since the points are not fixed the generator is not a part of
    /// the circuit description, however it is less efficient for a program
    /// width of 4.
    ///
    /// Adds two curve points
    pub fn gate_add_point(
        &mut self,
        a: WitnessPoint,
        b: WitnessPoint,
    ) -> WitnessPoint {
        // In order to verify that two points were correctly added
        // without going over a degree 4 polynomial, we will need
        // x_1, y_1, x_2, y_2
        // x_3, y_3, x_1 * y_2

        let x_1 = a.x;
        let y_1 = a.y;
        let x_2 = b.x;
        let y_2 = b.y;

        let p1 = JubJubAffine::from_raw_unchecked(
            self.witnesses[&x_1],
            self.witnesses[&y_1],
        );

        let p2 = JubJubAffine::from_raw_unchecked(
            self.witnesses[&x_2],
            self.witnesses[&y_2],
        );

        let point: JubJubAffine = (JubJubExtended::from(p1) + p2).into();
        let x_3 = point.get_x();
        let y_3 = point.get_y();

        let x1_y2 = self.witnesses[&x_1] * self.witnesses[&y_2];

        // Add the rest of the prepared points into the composer
        let x_1_y_2 = self.append_witness(x1_y2);
        let x_3 = self.append_witness(x_3);
        let y_3 = self.append_witness(y_3);

        self.w_l.extend(&[x_1, x_3]);
        self.w_r.extend(&[y_1, y_3]);
        self.w_o.extend(&[x_2, self.constant_zero()]);
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
            self.constant_zero(),
            x_1_y_2,
            self.n,
        );
        self.n += 1;

        WitnessPoint { x: x_3, y: y_3 }
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
        composer: &mut TurboComposer,
        a: WitnessPoint,
        b: WitnessPoint,
    ) -> WitnessPoint {
        let zero = composer.constant_zero();

        let x1 = a.x;
        let y1 = a.y;

        let x2 = b.x;
        let y2 = b.y;

        // x1 * y2
        let x1_y2 = composer.gate_mul(
            x1,
            y2,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // y1 * x2
        let y1_x2 = composer.gate_mul(
            y1,
            x2,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // y1 * y2
        let y1_y2 = composer.gate_mul(
            y1,
            y2,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // x1 * x2
        let x1_x2 = composer.gate_mul(
            x1,
            x2,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // d x1x2 * y1y2
        let d_x1_x2_y1_y2 = composer.gate_mul(
            x1_x2,
            y1_y2,
            zero,
            EDWARDS_D,
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // x1y2 + y1x2
        let zero = composer.constant_zero();
        let x_numerator = composer.gate_add(
            x1_y2,
            y1_x2,
            zero,
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // y1y2 - a * x1x2 (a=-1) => y1y2 + x1x2
        let y_numerator = composer.gate_add(
            y1_y2,
            x1_x2,
            zero,
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // 1 + dx1x2y1y2
        let x_denominator = composer.gate_add(
            d_x1_x2_y1_y2,
            zero,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::one(),
            None,
        );

        // Compute the inverse
        let inv_x_denom =
            composer.evaluate_witness(&x_denominator).invert().unwrap();
        let inv_x_denom = composer.append_witness(inv_x_denom);

        // Assert that we actually have the inverse
        // inv_x * x = 1
        composer.append_gate(
            x_denominator,
            inv_x_denom,
            zero,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            None,
        );

        // 1 - dx1x2y1y2
        let y_denominator = composer.gate_add(
            d_x1_x2_y1_y2,
            zero,
            zero,
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::one(),
            None,
        );

        let inv_y_denom =
            composer.evaluate_witness(&y_denominator).invert().unwrap();
        let inv_y_denom = composer.append_witness(inv_y_denom);

        // Assert that we actually have the inverse
        // inv_y * y = 1
        composer.append_gate(
            y_denominator,
            inv_y_denom,
            zero,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            None,
        );

        // We can now use the inverses

        let x_3 = composer.gate_mul(
            inv_x_denom,
            x_numerator,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        let y_3 = composer.gate_mul(
            inv_y_denom,
            y_numerator,
            zero,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        WitnessPoint { x: x_3, y: y_3 }
    }

    #[test]
    fn test_curve_addition() {
        let res = gadget_tester(
            |composer| {
                let expected_point: JubJubAffine =
                    (JubJubExtended::from(GENERATOR)
                        + JubJubExtended::from(GENERATOR))
                    .into();
                let x = composer.append_witness(GENERATOR.get_x());
                let y = composer.append_witness(GENERATOR.get_y());
                let point_a = WitnessPoint { x, y };
                let point_b = WitnessPoint { x, y };

                let point = composer.gate_add_point(point_a, point_b);
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
