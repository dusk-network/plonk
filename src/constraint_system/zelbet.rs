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
        });

        let s_ik_var = self.add_input(BlsScalar::from_raw(s_i[25].0));
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
    /// Assumes input BlsScalar value is in reduced form, but outputs the result
    /// in Montgomery form. Also outputs c_i, z_i, and a boolean counter used to determine c_i
    pub fn s_box(
        &mut self,
        input: Variable,
        counter: bool,
    ) -> (Variable, Variable, bool, Variable) {
        let value = u256(self.variables[&input].0);
        let mut permutation = BlsScalar::zero();
        let mut c_i = self.zero_var;
        let mut counter_new = false;
        let mut z_i = self.zero_var;
        if value < u256([659, 0, 0, 0]) {
            permutation = BlsScalar(SBOX_U256[value.0[0] as usize].0);
            c_i = self.add_input(BlsScalar::one());
            counter_new = true;
        } else {
            permutation = BlsScalar(value.0);
            z_i = self.add_input(BlsScalar::one());
            if value > u256([659, 0, 0, 0]) {
                c_i = self.add_input(BlsScalar::from(2));
                counter_new = true
            } else {
                if counter == true {
                    c_i = self.add_input(BlsScalar::from(2));
                    counter_new = true
                } else {
                    c_i = self.zero_var
                }
            }
        }

        // let permutation_var =
        // self.add_input(BlsScalar::from_raw(permutation.0));
        // self.plookup_gate(input, input, permutation_var, None,
        // BlsScalar::zero())
        (
            self.add_input(BlsScalar::from_raw(permutation.0)),
            c_i,
            counter_new,
            z_i,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use super::*;
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

    // #[test]
    // fn test_s_box() {
    //     let res = gadget_tester(
    //         |composer| {
    //             let one = composer.add_input(BlsScalar::one().reduce());
    //             let counter = false;
    //             let output = composer.s_box(one, counter);

    //             // composer.constrain_to_constant(
    //             //     output.0,
    //             //     BlsScalar::from_raw([187, 0, 0, 0]),
    //             //     BlsScalar::zero(),
    //             // );
    //             (0..30).for_each(|k| {
    //                 composer.constrain_to_constant(
    //                 one,
    //                 BlsScalar::one(),
    //                 BlsScalar::zero(),
    //             );
    //         });
    //             assert_eq!(composer.variables[&output.1], BlsScalar::one());
    //             assert_eq!(output.2, true);
    //             assert_eq!(composer.variables[&output.3], BlsScalar::zero());
    //             println!("circuit size is {:?}", composer.circuit_size());
    //             composer.check_circuit_satisfied();
    //         },
    //         5,
    //     );
    //     assert!(res.is_ok());
    // }
}
