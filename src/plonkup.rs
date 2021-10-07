// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Module containing the plonkup works.
//! Plonkup is the protcol for using
//! precomputed and stored tables of values
//! for specific functions to determine the
//! output of gates within a circuit, without
//! computing them.

pub(crate) mod multiset;
pub(crate) mod table;

pub use multiset::MultiSet;
pub use table::hash_tables::constants;
pub use table::{
    lookup_table::{PlonkupTable3Arity, PlonkupTable4Arity},
    preprocess::{PreprocessedTable3Arity, PreprocessedTable4Arity},
    witness_table::{WitnessTable3Arity, WitnessTable4Arity},
};
