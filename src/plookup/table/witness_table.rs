// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::bls12_381::BlsScalar;
use crate::plookup::error::PlookupErrors;
use crate::plookup::MultiSet;
use crate::plookup::{PlookupTable3Arity, PlookupTable4Arity};

/// This witness table contains quieries
/// to a lookup table for lookup gates
/// This table is of arity 3.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct WitnessTable3Arity {
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
}

/// This witness table contains quieries
/// to a lookup table for lookup gates
/// This table is of arity 3.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct WitnessTable4Arity {
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

impl Default for WitnessTable3Arity {
    fn default() -> Self {
        WitnessTable3Arity::new()
    }
}

impl WitnessTable3Arity {
    /// Initialises an empty witness table of arity 4
    pub fn new() -> Self {
        WitnessTable3Arity {
            f_1: MultiSet::new(),
            f_2: MultiSet::new(),
            f_3: MultiSet::new(),
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
    ) {
        self.f_1.push(left_wire_val);
        self.f_2.push(right_wire_val);
        self.f_3.push(output_wire_val);
    }

    /// Attempts to look up a value from a lookup table. If successful, all three
    /// elements are pushed to their respective multisets.
    pub fn value_from_table(
        &mut self,
        lookup_table: &PlookupTable3Arity,
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

impl Default for WitnessTable4Arity {
    fn default() -> Self {
        WitnessTable4Arity::new()
    }
}

impl WitnessTable4Arity {
    /// Initialses empty witness table of arity 4
    pub fn new() -> Self {
        WitnessTable4Arity {
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
        lookup_table: &PlookupTable4Arity,
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
#[cfg(test)]
mod test {
    use super::*;
    use crate::plookup::{PlookupTable3Arity, PlookupTable4Arity};

    #[test]
    fn test_lookup_fuctionality_arity3() {
        // Build lookup table
        let lookup_table = PlookupTable3Arity::xor_table(0, 3);

        // Instantiate empty multisets of wire values in witness table
        let mut f = WitnessTable3Arity::new();

        // Read values from lookup table and insert into witness table
        assert!(f
            .value_from_table(&lookup_table, BlsScalar::from(2), BlsScalar::from(5))
            .is_ok());

        // Check that non existent elements cause a failure
        assert!(f
            .value_from_table(&lookup_table, BlsScalar::from(25), BlsScalar::from(5))
            .is_err());
    }

    #[test]
    fn test_lookup_fuctionality_arity4() {
        // Build empty lookup tables
        let mut lookup_table = PlookupTable4Arity::new();

        // Add a consecutive set of tables, with
        // XOR operationd and addition operations
        lookup_table.insert_multi_xor(0, 4);
        lookup_table.insert_multi_add(2, 3);

        // Build empty witness table
        let mut f = WitnessTable4Arity::new();

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
