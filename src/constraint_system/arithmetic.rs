// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::{TurboComposer, Witness};
use dusk_bls12_381::BlsScalar;

impl TurboComposer {
    /// Evaluate and return `o` by appending a new constraint into the circuit.
    ///
    /// `o := q_l · a + q_r · b + q_4 · d + q_c + PI`
    pub fn gate_add(
        &mut self,
        a: Witness,
        b: Witness,
        d: Witness,
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_4: BlsScalar,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Witness {
        // Compute the output wire
        let o = q_l * self.witnesses[&a]
            + q_r * self.witnesses[&b]
            + q_4 * self.witnesses[&d]
            + q_c
            + pi.unwrap_or_default();

        let o = self.append_witness(o);
        let q_o = -BlsScalar::one();

        self.append_gate(
            a,
            b,
            o,
            d,
            BlsScalar::zero(),
            q_l,
            q_r,
            q_o,
            q_4,
            q_c,
            pi,
        );

        o
    }

    /// Evaluate and return `o` by appending a new constraint into the circuit.
    ///
    /// `o := q_m · a · b + q_4 · d + q_c + PI`
    pub fn gate_mul(
        &mut self,
        a: Witness,
        b: Witness,
        d: Witness,
        q_m: BlsScalar,
        q_4: BlsScalar,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Witness {
        // Compute the output wire
        let o = q_m * self.witnesses[&a] * self.witnesses[&b]
            + q_4 * self.witnesses[&d]
            + q_c
            + pi.unwrap_or_default();

        let o = self.append_witness(o);
        let q_o = -BlsScalar::one();

        self.append_gate(
            a,
            b,
            o,
            d,
            q_m,
            BlsScalar::zero(),
            BlsScalar::zero(),
            q_o,
            q_4,
            q_c,
            pi,
        );

        o
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::constraint_system::helper::*;
    use dusk_bls12_381::BlsScalar;

    #[test]
    fn test_public_inputs() {
        let res = gadget_tester(
            |composer| {
                let one = composer.append_witness(BlsScalar::one());
                let zero = composer.constant_zero();

                let should_be_three = composer.gate_add(
                    one,
                    one,
                    zero,
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    Some(BlsScalar::one()),
                );

                composer.assert_equal_constant(
                    should_be_three,
                    BlsScalar::from(3),
                    None,
                );

                let should_be_four = composer.gate_add(
                    one,
                    one,
                    zero,
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    Some(BlsScalar::from(2)),
                );

                composer.assert_equal_constant(
                    should_be_four,
                    BlsScalar::from(4),
                    None,
                );
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_correct_add_mul_gate() {
        let res = gadget_tester(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) = 280
                let four = composer.append_witness(BlsScalar::from(4));
                let five = composer.append_witness(BlsScalar::from(5));
                let six = composer.append_witness(BlsScalar::from(6));
                let seven = composer.append_witness(BlsScalar::from(7));
                let zero = composer.constant_zero();

                let fourteen = composer.gate_add(
                    four,
                    five,
                    five,
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    None,
                );

                let twenty = composer.gate_add(
                    six,
                    seven,
                    seven,
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    None,
                );

                // There are quite a few ways to check the equation is correct,
                // depending on your circumstance If we already
                // have the output wire, we can constrain the output of the
                // mul_gate to be equal to it If we do not, we
                // can compute it using the `mul` If the output
                // is public, we can also constrain the output wire of the mul
                // gate to it. This is what this test does
                let output = composer.gate_mul(
                    fourteen,
                    twenty,
                    zero,
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    None,
                );

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
        let res = gadget_tester(
            |composer| {
                let zero = composer.constant_zero();
                let one = composer.append_witness(BlsScalar::one());

                let c = composer.gate_add(
                    one,
                    zero,
                    zero,
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::from(2u64),
                    None,
                );

                composer.assert_equal_constant(c, BlsScalar::from(3), None);
            },
            32,
        );
        assert!(res.is_ok())
    }

    #[test]
    fn test_correct_big_add_mul_gate() {
        let res = gadget_tester(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) + (8*9) = 352
                let four = composer.append_witness(BlsScalar::from(4));
                let five = composer.append_witness(BlsScalar::from(5));
                let six = composer.append_witness(BlsScalar::from(6));
                let seven = composer.append_witness(BlsScalar::from(7));
                let nine = composer.append_witness(BlsScalar::from(9));

                let fourteen = composer.gate_add(
                    four,
                    five,
                    five,
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    None,
                );

                let twenty = composer.gate_add(
                    six,
                    seven,
                    seven,
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    None,
                );

                let output = composer.gate_mul(
                    fourteen,
                    twenty,
                    nine,
                    BlsScalar::one(),
                    BlsScalar::from(8),
                    BlsScalar::zero(),
                    None,
                );

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
        let res = gadget_tester(
            |composer| {
                // Verify that (5+5) * (6+7) != 117
                let five = composer.append_witness(BlsScalar::from(5));
                let six = composer.append_witness(BlsScalar::from(6));
                let seven = composer.append_witness(BlsScalar::from(7));
                let zero = composer.constant_zero();

                let five_plus_five = composer.gate_add(
                    five,
                    five,
                    zero,
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    None,
                );

                let six_plus_seven = composer.gate_add(
                    six,
                    seven,
                    zero,
                    BlsScalar::one(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    None,
                );

                let output = composer.gate_mul(
                    five_plus_five,
                    six_plus_seven,
                    zero,
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    None,
                );

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
