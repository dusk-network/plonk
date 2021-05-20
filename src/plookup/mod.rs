// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Module containing the plookup works.
//! Plookup is the protcol for using
//! precomputed and stored tables of values
//! for specific functions to determine the
//! output of gates within a circuit, without
//! computing them.

pub mod error;
/// Multiset
pub mod multiset;
/// hello
pub mod table;
// pub mod plookup;

pub use error::PlookupErrors;
pub use multiset::MultiSet;
pub use table::{
    lookup_table::{PlookupTable3Arity, PlookupTable4Arity},
    preprocess::{PreprocessedTable3Arity, PreprocessedTable4Arity},
    witness_table::{WitnessTable3Arity, WitnessTable4Arity},
};
