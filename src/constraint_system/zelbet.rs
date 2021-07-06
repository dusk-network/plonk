// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::too_many_arguments)]

use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use crate::plookup::table::hash_tables::DECOMPOSITION_S_I;
use crate::plookup::table::hash_tables::INVERSES_S_I;
use bigint::U256 as u256;
use dusk_bls12_381::BlsScalar;

impl StandardComposer {
    /// Gadget that conducts the bar decomposition, returning the 27-entry
    /// breakdown and adding relevant gates. The input and output variables
    /// are all in Montgomery form, but non-Montgomery form is used within.
    /// [x_27, ..., x_2, x_1] & note that s_i_decomposition should be input
    /// in Montgomery form
    pub fn decomposition_gadget(
        &mut self,
        x: Variable,
        s_i_decomposition: [Variable; 27],
    ) -> ([Variable; 27], [u256; 27]) {
        let mut nibbles_mont = [x; 27];
        let mut nibbles_reduced = [u256::zero(); 27];
        // Reduced form needed for the modular operations
        let reduced_input = self.variables[&x].reduce();
        let mut intermediate = u256(reduced_input.0);
        let mut remainder = u256::zero();

        (0..27).for_each(|k| {
            match k < 26 {
                true => {
                    remainder = intermediate % u256(DECOMPOSITION_S_I[k].0);
                    let intermediate_scalar: BlsScalar =
                        BlsScalar((intermediate - remainder).0) * INVERSES_S_I[k];
                    intermediate = u256(intermediate_scalar.0);
                }
                false => remainder = intermediate,
            }

            nibbles_mont[k] = self.add_input(BlsScalar::from_raw(remainder.0));
            nibbles_reduced[k] = remainder;
        });

        // x' = x_1 * s_2 + x_2, this is the start of the composition
        let mut acc = self.big_mul(
            BlsScalar::one(),
            nibbles_mont[26],
            s_i_decomposition[25],
            Some((BlsScalar::one(), nibbles_mont[25])),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        (1..26).for_each(|k| {
            acc = self.big_mul(
                BlsScalar::one(),
                acc,
                s_i_decomposition[25 - k],
                Some((BlsScalar::one(), nibbles_mont[25 - k])),
                BlsScalar::zero(),
                BlsScalar::zero(),
            );
        });

        self.constrain_to_constant(acc, self.variables[&x], BlsScalar::zero());

        (nibbles_mont, nibbles_reduced)
    }
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use crate::plookup::table::hash_tables::constants::S_I_DECOMPOSITION_MONTGOMERY;
    use dusk_bls12_381::BlsScalar;

    #[test]
    fn test_decomposition() {
        let res = gadget_tester(
            |composer| {
                let one = composer.add_input(BlsScalar::one());
                let mut s_i_decomposition = [one; 27];
                (0..27).for_each(|k| {
                    s_i_decomposition[k] = composer.add_input(S_I_DECOMPOSITION_MONTGOMERY[k]);
                });
                let (output_mont, _output_reduced) =
                    composer.decomposition_gadget(one, s_i_decomposition);
                (1..27).for_each(|k| {
                    composer.constrain_to_constant(
                        output_mont[k],
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );
                });
                // Check x_27 = 1, bearing in mind that x_1 is not in Montgomery form
                composer.constrain_to_constant(output_mont[0], BlsScalar::one(), BlsScalar::zero());

                let minus_three = composer.add_input(-BlsScalar::from(3));
                let output2 = composer.decomposition_gadget(minus_three, s_i_decomposition);
                // Expetced output derived from out of circuit version
                let expected_output = [
                    658, 660, 673, 663, 674, 682, 687, 683, 669, 684, 672, 666, 680, 662, 686, 668,
                    661, 678, 692, 686, 689, 660, 690, 687, 683, 674, 678, 658, 660, 673, 663, 674,
                    682, 687, 683, 669, 684, 672, 666, 680, 662, 686, 668, 661, 678, 692, 686, 689,
                    660, 690, 687, 683, 674, 678, 658, 660, 673, 663, 674, 682, 687, 683, 669, 684,
                    672, 666, 680, 662, 686, 668, 661, 678, 692, 686, 689, 660, 690, 687, 683, 674,
                    678,
                ];
                (0..27).for_each(|k| {
                    composer.constrain_to_constant(
                        output2.0[k],
                        BlsScalar::from(expected_output[k]),
                        BlsScalar::zero(),
                    );
                })
            },
            500,
        );
        assert!(res.is_ok());
    }
}
