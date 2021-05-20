// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::too_many_arguments)]

use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use crate::plookup::PlookupTable3Arity;
use bigint::U256 as u256;
use dusk_bls12_381::BlsScalar;

impl StandardComposer {
    /// Gadget that conducts the bar decomposition
    /// and returns the 27-entry breakdown, whilst
    /// adding all the relevant gates. The 27 Scalars
    /// are kept in raw form, not Montgomery.
    pub fn decomposition_gadget(
        &mut self,
        x: Variable,
        s_i: [BlsScalar; 27],
        s_i_inv: [BlsScalar; 27],
    ) -> [Variable; 27] {
        let mut nibbles = [x; 27];
        let mut intermediate = u256(self.variables[&x].reduce().0);
        let mut remainder = u256::zero();

        (0..27).for_each(|k| {
            let s_ik = u256(s_i[k].0);
            remainder = intermediate % s_ik;

            match k < 26 {
                true => {
                    let intermediate_scalar: BlsScalar =
                        BlsScalar((intermediate - remainder).0) * s_i_inv[k];
                    intermediate = u256(intermediate_scalar.0);
                }
                false => remainder = intermediate,
            }

            nibbles[k] = self.add_input(BlsScalar(remainder.0));
            self.range_gate(nibbles[k], s_ik.as_u32() as usize);
        });

        let s_ik_var = self.add_input(s_i[25]);
        let mut acc = self.big_mul(
            BlsScalar::one(),
            nibbles[26],
            s_ik_var,
            Some((BlsScalar::one(), nibbles[25])),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        (1..26).for_each(|k| {
            let s_ik_var = self.add_input(s_i[25-k]);
            acc = self.big_mul(
                BlsScalar::one(),
                acc,
                s_ik_var,
                Some((BlsScalar::one(), nibbles[25 - k])),
                BlsScalar::zero(),
                BlsScalar::zero(),
            );
        });

        nibbles
    }

    /// S-box using hash tables
    /// Assumes input BlsScalar value is reduced form,
    /// and permuted value is also reduced form.
    pub fn s_box(
        &mut self,
        input: Variable,
        bar_table: PlookupTable3Arity,
    ) -> Variable {
        let value = u256(self.variables[&input].0);
        let permutation = match value < u256([659, 0, 0, 0]) {
            true => bar_table.lookup(BlsScalar(value.0), BlsScalar(value.0)).unwrap(),
            false => BlsScalar(value.0),
        };

        let permutation_var = self.add_input(permutation);
        self.plookup_gate(input, input, permutation_var, None, BlsScalar::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use crate::{constraint_system::StandardComposer, plookup::PlookupTable3Arity};
    use dusk_bls12_381::BlsScalar;

    #[test]
    fn decompo_test() {
        let composer = &mut StandardComposer::new();
        let table = PlookupTable3Arity::s_box_table();
        let eight = composer.add_witness_to_circuit_description(BlsScalar::from(8));
        composer.decomposition_gadget(eight, [BlsScalar::from(8); 27], [BlsScalar::from(8); 27]);
        println!("{:?}", composer.circuit_size());
    }
}
