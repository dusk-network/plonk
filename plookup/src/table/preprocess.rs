// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{kzg10, multiset::MultiSet};
use algebra::{bls12_381::Fr, Bls12_381};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use poly_commit::kzg10::{Commitment, Powers};
use std::collections::HashMap;
use table::lookup_table::{PlookupTable3Arity, PlookupTable4Arity};
/// This table will be the preprocessed version of the 
/// precomputed table, T. This structure is passed to the 
/// proof alongside the table of witness values. 
pub struct PreProcessedTableArity3 {
    pub n: usize,
    pub t_1: (MultiSet, Commitment<Bls12_381>, Polynomial<Fr>),
    pub t_2: (MultiSet, Commitment<Bls12_381>, Polynomial<Fr>),
    pub t_3: (MultiSet, Commitment<Bls12_381>, Polynomial<Fr>),
}

impl PreProcessedTableArity3 { 
    fn preprocess(table: PlookupTable3Arity, commit_key: &Powers<Bls12_381>, n: usize) -> Self
}
pub struct PreProcessedTableArity4 {
    pub n: usize,
    pub t_1: (MultiSet, Commitment<Bls12_381>, Polynomial<Fr>),
    pub t_2: (MultiSet, Commitment<Bls12_381>, Polynomial<Fr>),
    pub t_3: (MultiSet, Commitment<Bls12_381>, Polynomial<Fr>),
    pub t_4: (MultiSet, Commitment<Bls12_381>, Polynomial<Fr>),
}


