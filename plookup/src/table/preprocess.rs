// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::multiset::MultiSet;
use crate::table::lookup_table::{PlookupTable3Arity, PlookupTable4Arity};
use dusk_plonk::bls12_381::{BlsScalar, G1Affine};
use dusk_plonk::commitment_scheme::kzg10::{AggregateProof, CommitKey, Commitment, OpeningKey};
use dusk_plonk::fft::{EvaluationDomain, Polynomial};
use std::collections::HashMap;
/// This table will be the preprocessed version of the
/// precomputed table, T. This structure is passed to the
/// proof alongside the table of witness values.
pub struct PreProcessedTableArity3 {
    pub n: usize,
    pub t_1: (MultiSet, Commitment, Polynomial),
    pub t_2: (MultiSet, Commitment, Polynomial),
    pub t_3: (MultiSet, Commitment, Polynomial),
}

// impl PreProcessedTableArity3 {
//     fn preprocess(table: PlookupTable3Arity, commit_key: &CommitKey, n: usize) -> Self
// }

pub struct PreProcessedTableArity4 {
    pub n: usize,
    pub t_1: (MultiSet, Commitment, Polynomial),
    pub t_2: (MultiSet, Commitment, Polynomial),
    pub t_3: (MultiSet, Commitment, Polynomial),
    pub t_4: (MultiSet, Commitment, Polynomial),
}

// impl PreProcessedTableArity4 {
//     fn preprocess(table: PlookupTable4Arity, commit_key: &CommitKey, n: usize) -> Self
// }
