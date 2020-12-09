// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::PlookupErrors;
use crate::multiset::MultiSet;
use crate::table::lookup_table::{PlookupTable3Arity, PlookupTable4Arity};
use dusk_plonk::bls12_381::BlsScalar;


pub struct WitnessTable3Arity {
    pub f_1: MultiSet,
    pub f_2: MultiSet,
    pub f_3: MultiSet,
}

pub struct WitnessTable4Arity {
    pub f_1: MultiSet,
    pub f_2: MultiSet,
    pub f_3: MultiSet,
    pub f_4: MultiSet,
}

impl WitnessTable3Arity {
    /// This allows the witness table to be filled directly without
    /// taking any vaules, or the the results, from the lookup table.
    /// If the values do no exists in the lookup table, then the proof
    /// will fail when witness and preprocessed tables are concatenated.
    pub fn from_wire_values(
        &mut self,
        left_wire_val: BlsScalar,
        right_wire_val: BlsScalar,
        output_wire_val: BlsScalar,
    ) {
        self.f_1.push(left_wire_val);
        self.f_2.push(right_wire_val);
        self.f_3.push(output_wire_val);
    }

    /// Attempts to look up a value from a lookup table. If successful, all three
    /// elements are pushed to their respective multisets.
    pub fn value_from_table(
        &mut self,
        lookup_table: PlookupTable3Arity,
        left_wire_val: BlsScalar,
        right_wire_val: BlsScalar,
    ) -> Result<(), PlookupErrors> {
        let output_wire_val = lookup_table.lookup(left_wire_val, right_wire_val)?;
        self.f_1.push(left_wire_val);
        self.f_2.push(right_wire_val);
        self.f_3.push(output_wire_val);
        Ok(())
    }
}

impl WitnessTable4Arity {
    /// This allows the witness table to be filled directly without
    /// taking any vaules, or the the results, from the lookup table.
    /// If the values do no exists in the lookup table, then the proof
    /// will fail when witness and preprocessed tables are concatenated.
    pub fn from_wire_values(
        &mut self,
        left_wire_val: BlsScalar,
        right_wire_val: BlsScalar,
        output_wire_val: BlsScalar,
        fourth_wire_val: BlsScalar,
    ) {
        self.f_1.push(left_wire_val);
        self.f_2.push(right_wire_val);
        self.f_3.push(output_wire_val);
        self.f_4.push(fourth_wire_val);
    }

    /// Attempts to look up a value from a lookup table. If successful, all four
    /// elements are pushed to their respective multisets.
    pub fn value_from_table(
        &mut self,
        lookup_table: PlookupTable4Arity,
        left_wire_val: BlsScalar,
        right_wire_val: BlsScalar,
        fourth_wire_val: BlsScalar,
    ) -> Result<(), PlookupErrors> {
        let output_wire_val =
            lookup_table.lookup(left_wire_val, right_wire_val, fourth_wire_val)?;
        self.f_1.push(left_wire_val);
        self.f_2.push(right_wire_val);
        self.f_3.push(output_wire_val);
        self.f_4.push(fourth_wire_val);
        Ok(())
    }
}
