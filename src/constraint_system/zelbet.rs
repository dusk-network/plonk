// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::too_many_arguments)]

use std::collections::btree_map::VacantEntry;

use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use crate::plookup::PlookupTable3Arity;
// use crate::constraint_system::zelbet;
use bigint::U256 as u256;
use dusk_bls12_381::BlsScalar;

impl StandardComposer {
    /// Gadget that conducts the bar decomposition
    /// and returns the 27-entry breakdown, whilst
    /// adding all the relevant gates. The 27 Scalars
    /// are kept in raw form, not Montgomery - will 
    /// this cause a problem in the proof system?
    pub fn decomposition_gadget(
        &mut self,
        x: Variable,
        s_i_var: [Variable; 27],
        s_i_inv: [BlsScalar; 27],
    ) -> [Variable; 27] {
        let mut nibbles = [x; 27];
        let mut intermediate = u256(self.variables[&x].reduce().0);
        let mut remainder = u256::zero();

        (0..27).for_each(|k| {
            let s_i = u256(self.variables[&s_i_var[k]].0);
            remainder = intermediate % s_i;

            match k < 26 {
                true => {
                    let intermediate_scalar: BlsScalar =
                        BlsScalar((intermediate - remainder).0) * s_i_inv[k];
                    intermediate = u256(intermediate_scalar.0);
                }
                false => remainder = intermediate,
            }

            nibbles[k] = self.add_input(BlsScalar(remainder.0));
            self.range_gate(
                nibbles[k],
                s_i.as_u32() as usize,
            );
        });

        let mut acc = self.big_mul(
            BlsScalar::one(),
            nibbles[26],
            s_i_var[25],
            Some((BlsScalar::one(), nibbles[25])),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        (1..26).for_each(|k| {
            acc = self.big_mul(
                BlsScalar::one(),
                acc,
                s_i_var[25 - k],
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
    pub fn s_box(&mut self, input: Variable, table: PlookupTable3Arity) -> Variable {
        let value = u256(self.variables[&input].0);
        let bar_table = PlookupTable3Arity::s_box_table();
        let permutation = match value < 659 {
            true => bar_table.lookup(value, value),
            false => value,
        };

        let new_var = self.add_input(BlsScalar(permutation.0));
        self.plookup_gate(input, input, permutation, None, BlsScalar::one(), BlsScalar::one(), BlsScalar::one(), BlsScalar::zero(), BlsScalar::zero(), BlsScalar::zero())
    }
}