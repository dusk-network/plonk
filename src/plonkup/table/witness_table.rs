// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;
use crate::plonkup::IndexTable;
use crate::plonkup::MultiSet;
use dusk_bls12_381::BlsScalar;

/// This witness table contains quieries
/// to a lookup table for lookup gates
/// This table is of arity 3.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct WitnessTable {
    /// This column represents the
    /// first values inside the lookup
    /// table. At gate checks, this
    /// can be regarded as the first
    /// wire
    pub f_1: MultiSet,

    /// This column represents the
    /// first values inside the lookup
    /// table. At gate checks, this
    /// can be regarded as the second
    /// wire
    pub f_2: MultiSet,

    /// This column represents the
    /// first values inside the lookup
    /// table. At gate checks, this
    /// can be regarded as the third
    /// wire
    pub f_3: MultiSet,

    /// This column represents the
    /// first values inside the lookup
    /// table. At gate checks, this
    /// can be regarded as the fourth
    /// wire
    pub f_4: MultiSet,
}

impl Default for WitnessTable {
    fn default() -> Self {
        WitnessTable::new()
    }
}

impl WitnessTable {
    /// Initialses empty witness table of arity 4
    pub fn new() -> Self {
        WitnessTable {
            f_1: MultiSet::new(),
            f_2: MultiSet::new(),
            f_3: MultiSet::new(),
            f_4: MultiSet::new(),
        }
    }
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
        lookup_table: &IndexTable,
        left_wire_val: BlsScalar,
        right_wire_val: BlsScalar,
        fourth_wire_val: BlsScalar,
    ) -> Result<(), Error> {
        let output_wire_val = lookup_table.lookup(
            left_wire_val,
            right_wire_val,
            fourth_wire_val,
        )?;
        self.f_1.push(left_wire_val);
        self.f_2.push(right_wire_val);
        self.f_3.push(output_wire_val);
        self.f_4.push(fourth_wire_val);
        Ok(())
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::plonkup::IndexTable;

    #[test]
    fn test_lookup() {
        // Build empty lookup tables
        let mut lookup_table = IndexTable::new();

        // Add a consecutive set of tables, with
        // XOR operationd and addition operations
        lookup_table.insert_multi_xor(0, 4);
        lookup_table.insert_multi_add(2, 3);

        // Build empty witness table
        let mut f = WitnessTable::new();

        // Check for output of wires within lookup table and
        // if they exist input them to the witness table
        assert!(f
            .value_from_table(
                &lookup_table,
                BlsScalar::from(2),
                BlsScalar::from(3),
                -BlsScalar::one()
            )
            .is_ok());
        assert!(f
            .value_from_table(
                &lookup_table,
                BlsScalar::from(4),
                BlsScalar::from(6),
                BlsScalar::zero()
            )
            .is_ok());

        // Check that values not contained in the lookup table
        // do not get added to the witness table
        assert!(f
            .value_from_table(
                &lookup_table,
                BlsScalar::from(22),
                BlsScalar::from(1),
                -BlsScalar::one()
            )
            .is_err());
        assert!(f
            .value_from_table(
                &lookup_table,
                BlsScalar::from(0),
                BlsScalar::from(1),
                BlsScalar::zero()
            )
            .is_err());
    }
}
