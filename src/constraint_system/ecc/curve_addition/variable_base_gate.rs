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
    /// Adds two curve points by consuming 2 gates.
    pub fn component_add_point(
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

        // TODO encapsulate this gate addition into a generic `append` method
        // The function must be a special case of `append_gate` because of
        // `q_arith` and `q_variable_group_add`

        self.a_w.extend(&[x_1, x_3]);
        self.b_w.extend(&[y_1, y_3]);
        self.c_w.extend(&[x_2, Self::constant_zero()]);
        self.d_w.extend(&[y_2, x_1_y_2]);
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
        self.q_k.extend(&zeros);

        self.q_variable_group_add.push(BlsScalar::one());
        self.q_variable_group_add.push(BlsScalar::zero());

        self.perm.add_witnesses_to_map(x_1, y_1, x_2, y_2, self.n);
        self.n += 1;

        self.perm.add_witnesses_to_map(
            x_3,
            y_3,
            Self::constant_zero(),
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
    use crate::constraint_system::Constraint;
    use dusk_jubjub::{EDWARDS_D, GENERATOR, GENERATOR_EXTENDED};

    /// Adds two curve points together using the classical point addition
    /// algorithm. This method is slower than WNaf and is just meant to be the
    /// source of truth to test the WNaf method.
    pub fn classical_point_addition(
        composer: &mut TurboComposer,
        a: WitnessPoint,
        b: WitnessPoint,
    ) -> WitnessPoint {
        let x1 = a.x;
        let y1 = a.y;

        let x2 = b.x;
        let y2 = b.y;

        // x1 * y2
        let constraint = Constraint::new().mult(1).a(x1).b(y2);
        let x1_y2 = composer.gate_mul(constraint);

        // y1 * x2
        let constraint = Constraint::new().mult(1).a(y1).b(x2);
        let y1_x2 = composer.gate_mul(constraint);

        // y1 * y2
        let constraint = Constraint::new().mult(1).a(y1).b(y2);
        let y1_y2 = composer.gate_mul(constraint);

        // x1 * x2
        let constraint = Constraint::new().mult(1).a(x1).b(x2);
        let x1_x2 = composer.gate_mul(constraint);

        // d x1x2 * y1y2
        let constraint = Constraint::new().mult(EDWARDS_D).a(x1_x2).b(y1_y2);
        let d_x1_x2_y1_y2 = composer.gate_mul(constraint);

        // x1y2 + y1x2
        let constraint = Constraint::new().left(1).right(1).a(x1_y2).b(y1_x2);
        let x_numerator = composer.gate_add(constraint);

        // y1y2 - a * x1x2 (a=-1) => y1y2 + x1x2
        let constraint = Constraint::new().left(1).right(1).a(y1_y2).b(x1_x2);
        let y_numerator = composer.gate_add(constraint);

        // 1 + dx1x2y1y2
        let constraint = Constraint::new().left(1).constant(1).a(d_x1_x2_y1_y2);
        let x_denominator = composer.gate_add(constraint);

        // Compute the inverse
        let inv_x_denom = unsafe {
            composer.evaluate_witness(&x_denominator).invert().unwrap()
        };
        let inv_x_denom = composer.append_witness(inv_x_denom);

        // Assert that we actually have the inverse
        // inv_x * x = 1
        let constraint = Constraint::new()
            .mult(1)
            .constant(-BlsScalar::one())
            .a(x_denominator)
            .b(inv_x_denom);
        composer.append_gate(constraint);

        // 1 - dx1x2y1y2
        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .constant(1)
            .a(d_x1_x2_y1_y2);
        let y_denominator = composer.gate_add(constraint);

        let inv_y_denom = unsafe {
            composer.evaluate_witness(&y_denominator).invert().unwrap()
        };
        let inv_y_denom = composer.append_witness(inv_y_denom);

        // Assert that we actually have the inverse
        // inv_y * y = 1
        let constraint = Constraint::new()
            .mult(1)
            .constant(-BlsScalar::one())
            .a(y_denominator)
            .b(inv_y_denom);
        composer.append_gate(constraint);

        // We can now use the inverses
        let constraint =
            Constraint::new().mult(1).a(inv_x_denom).b(x_numerator);
        let x_3 = composer.gate_mul(constraint);

        let constraint =
            Constraint::new().mult(1).a(inv_y_denom).b(y_numerator);
        let y_3 = composer.gate_mul(constraint);

        WitnessPoint { x: x_3, y: y_3 }
    }

    #[test]
    fn test_curve_addition() {
        gadget_tester(
            |composer| {
                let expected = GENERATOR_EXTENDED + GENERATOR_EXTENDED;

                let point_a = composer.append_point(GENERATOR);
                let point_b = composer.append_point(GENERATOR);

                let point = composer.component_add_point(point_a, point_b);

                let point2 =
                    classical_point_addition(composer, point_a, point_b);

                composer.assert_equal_point(point, point2);
                composer.assert_equal_public_point(point, expected);
            },
            2000,
        )
        .expect("Curve addition failed");
    }
}
