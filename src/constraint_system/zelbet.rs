// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::too_many_arguments)]

use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use crate::plookup::{
    table::hash_tables::{DECOMPOSITION_S_I, INVERSES_S_I, SBOX_U256},
    PlookupTable3Arity,
};
use bigint::U256 as u256;
use dusk_bls12_381::BlsScalar;

impl StandardComposer {
    /// Gadget that conducts the bar decomposition
    /// and returns the 27-entry breakdown, whilst
    /// adding all the relevant gates. The 27 Scalars
    /// are kept in raw form, not Montgomery.
    /// [x_27, ..., x_2, x_1]
    pub fn decomposition_gadget(
        &mut self,
        x: Variable,
        s_i: [BlsScalar; 27],
        s_i_inv: [BlsScalar; 27],
    ) -> [Variable; 27] {
        let mut nibbles = [x; 27];
        let mut nibbles_montgomery = [x; 27];
        let reduced_input = self.variables[&x].reduce();
        let mut intermediate = u256(reduced_input.0);
        let mut remainder = u256::zero();

        (0..27).for_each(|k| {
            let s_ik = u256(s_i[k].0);

            match k < 26 {
                true => {
                    remainder = intermediate % s_ik;
                    let intermediate_scalar: BlsScalar =
                        BlsScalar((intermediate - remainder).0) * s_i_inv[k];
                    intermediate = u256(intermediate_scalar.0);
                }
                false => remainder = intermediate,
            }

            nibbles[k] = self.add_input(BlsScalar(remainder.0));
            nibbles_montgomery[k] = self.add_input(BlsScalar::from_raw(remainder.0));

            // Check that x_i >= 0 for each i
            self.range_gate(nibbles_montgomery[k], 10);
        });

        let one = self.add_input(BlsScalar::one());
        let s_ik_var = self.add_input(BlsScalar::from_raw(s_i[26].0));
        let mut difference = self.big_add(
            (BlsScalar::one(), s_ik_var),
            (-BlsScalar::one(), nibbles_montgomery[26]),
            Some((-BlsScalar::one(), one)),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        // Check that s_i-x_i-1 >= 0 for i=27, and subsequently for all i
        self.range_gate(difference, 10);

        let s_ik_var = self.add_input(BlsScalar::from_raw(s_i[25].0));
        difference = self.big_add(
            (BlsScalar::one(), s_ik_var),
            (-BlsScalar::one(), nibbles_montgomery[25]),
            Some((-BlsScalar::one(), one)),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        self.range_gate(difference, 10);

        // x' = x_1 * s_2 + x_2, this is the start of the composition
        let mut acc = self.big_mul(
            BlsScalar::one(),
            nibbles[26],
            s_ik_var,
            Some((BlsScalar::one(), nibbles[25])),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        (1..26).for_each(|k| {
            let s_ik_var = self.add_input(BlsScalar::from_raw(s_i[25 - k].0));
            let difference = self.big_add(
                (BlsScalar::one(), s_ik_var),
                (-BlsScalar::one(), nibbles_montgomery[25 - k]),
                Some((-BlsScalar::one(), one)),
                BlsScalar::zero(),
                BlsScalar::zero(),
            );
            self.range_gate(difference, 12);
            acc = self.big_mul(
                BlsScalar::one(),
                acc,
                s_ik_var,
                Some((BlsScalar::one(), nibbles[25 - k])),
                BlsScalar::zero(),
                BlsScalar::zero(),
            );
        });

        self.constrain_to_constant(acc, reduced_input, BlsScalar::zero());

        nibbles
    }

    /// S-box using hash tables
    /// Assumes input BlsScalar value is in reduced form,
    /// but outputs the result in Montgomery
    pub fn s_box(&mut self, input: Variable) -> Variable {
        let value = u256(self.variables[&input].0);
        let permutation = match value < u256([659, 0, 0, 0]) {
            true => BlsScalar(SBOX_U256[value.0[0] as usize].0),
            false => BlsScalar(value.0),
        };

        // let permutation_var =
        // self.add_input(BlsScalar::from_raw(permutation.0));
        // self.plookup_gate(input, input, permutation_var, None,
        // BlsScalar::zero())
        self.add_input(BlsScalar::from_raw(permutation.0))
    }
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use super::*;
    use crate::{constraint_system::StandardComposer, plookup::PlookupTable3Arity};
    use dusk_bls12_381::BlsScalar;

    #[test]
    fn test_decomposition() {
        let res = gadget_tester(
            |composer| {
                let one = composer.add_input(BlsScalar::one());
                let output = composer.decomposition_gadget(one, DECOMPOSITION_S_I, INVERSES_S_I);
                (1..27).for_each(|k| {
                    composer.constrain_to_constant(output[k], BlsScalar::zero(), BlsScalar::zero());
                });
                // Check x_27 = 1, bearing in mind that x_1 is not in Montgomery form
                composer.constrain_to_constant(
                    output[0],
                    BlsScalar::one().reduce(),
                    BlsScalar::zero(),
                );
            },
            800,
        );
        assert!(res.is_ok());
    }
}
