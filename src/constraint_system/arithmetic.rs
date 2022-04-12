// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::{Constraint, TurboComposer, Witness};
use dusk_bls12_381::BlsScalar;

impl TurboComposer {
    /// Evaluate and return `o` by appending a new constraint into the circuit.
    ///
    /// Set `q_o = (-1)` and override the output of the constraint with:
    /// `o := q_l · a + q_r · b + q_4 · d + q_c + PI`
    pub fn gate_add(&mut self, s: Constraint) -> Witness {
        let s = Constraint::arithmetic(&s).output(-BlsScalar::one());

        let o = self.append_output_witness(s);
        let s = s.o(o);

        self.append_gate(s);

        o
    }

    /// Evaluate and return `o` by appending a new constraint into the circuit.
    ///
    /// Set `q_o = (-1)` and override the output of the constraint with:
    /// `o := q_m · a · b + q_4 · d + q_c + PI`
    pub fn gate_mul(&mut self, s: Constraint) -> Witness {
        let s = Constraint::arithmetic(&s).output(-BlsScalar::one());

        let o = self.append_output_witness(s);
        let s = s.o(o);

        self.append_gate(s);

        o
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::constraint_system::{helper, Constraint};
    use dusk_bls12_381::BlsScalar;

    #[test]
    fn test_public_inputs() {
        helper::gadget_tester(
            |composer| {
                let one = composer.append_witness(BlsScalar::one());

                composer.append_dummy_gates();

                let constraint =
                    Constraint::new().left(1).right(1).public(1).a(one).b(one);
                let should_be_three = composer.gate_add(constraint);

                composer.assert_equal_constant(
                    should_be_three,
                    BlsScalar::from(3),
                    None,
                );

                let constraint =
                    Constraint::new().left(1).right(1).public(2).a(one).b(one);
                let should_be_four = composer.gate_add(constraint);

                composer.assert_equal_constant(
                    should_be_four,
                    BlsScalar::from(4),
                    None,
                );
            },
            200,
        )
        .expect("Failed to test circuit public inputs");
    }

    #[test]
    fn test_correct_add_mul_gate() {
        let res = helper::gadget_tester(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) = 280
                let four = composer.append_witness(BlsScalar::from(4));
                let five = composer.append_witness(BlsScalar::from(5));
                let six = composer.append_witness(BlsScalar::from(6));
                let seven = composer.append_witness(BlsScalar::from(7));

                let constraint = Constraint::new()
                    .left(1)
                    .right(1)
                    .fourth(1)
                    .a(four)
                    .b(five)
                    .d(five);
                let fourteen = composer.gate_add(constraint);

                let constraint = Constraint::new()
                    .left(1)
                    .right(1)
                    .fourth(1)
                    .a(six)
                    .b(seven)
                    .d(seven);
                let twenty = composer.gate_add(constraint);

                // There are quite a few ways to check the equation is correct,
                // depending on your circumstance If we already
                // have the output wire, we can constrain the output of the
                // mul_gate to be equal to it If we do not, we
                // can compute it using the `mul` If the output
                // is public, we can also constrain the output wire of the mul
                // gate to it. This is what this test does
                let constraint =
                    Constraint::new().mult(1).a(fourteen).b(twenty);
                let output = composer.gate_mul(constraint);

                composer.assert_equal_constant(
                    output,
                    BlsScalar::from(280),
                    None,
                );
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_correct_add_gate() {
        helper::gadget_tester(
            |composer| {
                let one = composer.append_witness(BlsScalar::one());

                let constraint = Constraint::new().left(1).constant(2).a(one);
                let c = composer.gate_add(constraint);

                composer.assert_equal_constant(c, BlsScalar::from(3), None);
            },
            32,
        )
        .expect("Circuit consistency failed");
    }

    #[test]
    fn test_correct_big_add_mul_gate() {
        let res = helper::gadget_tester(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) + (8*9) = 352
                let four = composer.append_witness(BlsScalar::from(4));
                let five = composer.append_witness(BlsScalar::from(5));
                let six = composer.append_witness(BlsScalar::from(6));
                let seven = composer.append_witness(BlsScalar::from(7));
                let nine = composer.append_witness(BlsScalar::from(9));

                let constraint = Constraint::new()
                    .left(1)
                    .right(1)
                    .fourth(1)
                    .a(four)
                    .b(five)
                    .d(five);
                let fourteen = composer.gate_add(constraint);

                let constraint = Constraint::new()
                    .left(1)
                    .right(1)
                    .fourth(1)
                    .a(six)
                    .b(seven)
                    .d(seven);
                let twenty = composer.gate_add(constraint);

                let constraint = Constraint::new()
                    .mult(1)
                    .fourth(8)
                    .a(fourteen)
                    .b(twenty)
                    .d(nine);
                let output = composer.gate_mul(constraint);

                composer.assert_equal_constant(
                    output,
                    BlsScalar::from(352),
                    None,
                );
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_incorrect_add_mul_gate() {
        let res = helper::gadget_tester(
            |composer| {
                // Verify that (5+5) * (6+7) != 117
                let five = composer.append_witness(BlsScalar::from(5));
                let six = composer.append_witness(BlsScalar::from(6));
                let seven = composer.append_witness(BlsScalar::from(7));

                let constraint =
                    Constraint::new().left(1).right(1).a(five).b(five);
                let five_plus_five = composer.gate_add(constraint);

                let constraint =
                    Constraint::new().left(1).right(1).a(six).b(seven);
                let six_plus_seven = composer.gate_add(constraint);

                let constraint = Constraint::new()
                    .mult(1)
                    .a(five_plus_five)
                    .b(six_plus_seven);
                let output = composer.gate_mul(constraint);

                composer.assert_equal_constant(
                    output,
                    BlsScalar::from(117),
                    None,
                );
            },
            200,
        );
        assert!(res.is_err());
    }
}
