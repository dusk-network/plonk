// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::too_many_arguments)]
use crate::table::lookup_table::{PlookupTable3Arity, PlookupTable4Arity};
use dusk_plonk::bls12_381::BlsScalar;
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::constraint_system::Variable;

/*
impl StandardComposer {
    /// Puts a plookup gates into the circuit, with the
    /// corresponding constraints.
    pub fn plookup(
        &mut self,
        f: Vec<BlsScalar>,
        t: Vec<BlsScalar>,
        q_plookup: BlsScalar,
        pi: BlsScalar,

    ) {


        self.q_arith.push(BlsScalar::zero();
        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());
        self.q_lookup.push(BlsScalar::one());

        self.public_inputs.push(pi);
        self.perm.add_variable_to_map(var, wire_data);

        self.n += 1;

    }
}
*/

/*
fn derive_challenge(&self) -> BlsScalar {
    unimplemented!()

}
*/
fn sort_and_pad(f: Vec<BlsScalar>, t: Vec<BlsScalar>) -> (usize, Vec<BlsScalar>, Vec<BlsScalar>) {
    let table_length = t.len();
    let f = if f.len() + 1 < table_length {
        padded(f, table_length - 1)
    } else {
        f.to_vec()
    };
    unimplemented!()
}

/// Pad the sorted version of the tables to have the same
/// length, in terms of power of two, as the precomputed
/// table. Fill in the extra row(s) with Zero.
pub fn padded(s: Vec<BlsScalar>, n: usize) -> Vec<BlsScalar> {
    unimplemented!()
}
