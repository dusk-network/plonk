// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::multiset::MultiSet;
use crate::table::lookup_table::{PlookupTable3Arity, PlookupTable4Arity};
use anyhow::{Error, Result};
use dusk_plonk::bls12_381::{BlsScalar, G1Affine};
use dusk_plonk::commitment_scheme::kzg10;
use dusk_plonk::commitment_scheme::kzg10::{CommitKey, Commitment};
use dusk_plonk::fft::{EvaluationDomain, Polynomial};

/// This table will be the preprocessed version of the
/// precomputed table, T. This structure is passed to the
/// proof alongside the table of witness values.
pub struct PreprocessedTable3Arity {
    pub n: u32,
    pub t_1: (MultiSet, Commitment, Polynomial),
    pub t_2: (MultiSet, Commitment, Polynomial),
    pub t_3: (MultiSet, Commitment, Polynomial),
}

impl PreprocessedTable3Arity {
    /// This function takes in a precomputed look up table and
    /// pads it to the length of the circuit entries, as a power
    /// of 2. The function then interpolates a polynomial from the
    /// padded table and makes a commitment to the poly. The
    /// outputted struct will be used in the proof alongside our
    /// circuit witness table.
    pub fn preprocess(
        table: PlookupTable3Arity,
        commit_key: &CommitKey,
        n: u32,
    ) -> Result<Self, Error> {
        let domain: EvaluationDomain = EvaluationDomain::new(n as usize).unwrap();

        let columned_table = table.vec_to_multiset();
        let mut t_1 = columned_table.0;
        let mut t_2 = columned_table.1;
        let mut t_3 = columned_table.2;

        t_1.pad(n);
        t_2.pad(n);
        t_3.pad(n);

        let t_1_poly = t_1.to_polynomial(&domain);
        let t_2_poly = t_2.to_polynomial(&domain);
        let t_3_poly = t_3.to_polynomial(&domain);

        let t_1_commit = commit_key.commit(&t_1_poly)?;
        let t_2_commit = commit_key.commit(&t_2_poly)?;
        let t_3_commit = commit_key.commit(&t_3_poly)?;

        Ok(PreprocessedTable3Arity {
            n,
            t_1: (t_1, t_1_commit, t_1_poly),
            t_2: (t_2, t_2_commit, t_2_poly),
            t_3: (t_3, t_3_commit, t_3_poly),
        })
    }
}

pub struct PreprocessedTable4Arity {
    pub n: u32,
    pub t_1: (MultiSet, Commitment, Polynomial),
    pub t_2: (MultiSet, Commitment, Polynomial),
    pub t_3: (MultiSet, Commitment, Polynomial),
    pub t_4: (MultiSet, Commitment, Polynomial),
}

impl PreprocessedTable4Arity {
    /// This function takes in a precomputed look up table and
    /// pads it to the length of the circuit entries, as a power
    /// of 2. The function then interpolates a polynomial from the
    /// padded table and makes a commitment to the poly. The
    /// outputted struct will be used in the proof alongside our
    /// circuit witness table.
    pub fn preprocess(
        table: PlookupTable4Arity,
        commit_key: &CommitKey,
        n: u32,
    ) -> Result<Self, Error> {
        let domain: EvaluationDomain = EvaluationDomain::new(n as usize).unwrap();

        let columned_table = table.vec_to_multiset();
        let mut t_1 = columned_table.0;
        let mut t_2 = columned_table.1;
        let mut t_3 = columned_table.2;
        let mut t_4 = columned_table.3;

        t_1.pad(n);
        t_2.pad(n);
        t_3.pad(n);
        t_4.pad(n);

        let t_1_poly = t_1.to_polynomial(&domain);
        let t_2_poly = t_2.to_polynomial(&domain);
        let t_3_poly = t_3.to_polynomial(&domain);
        let t_4_poly = t_4.to_polynomial(&domain);

        let t_1_commit = commit_key.commit(&t_1_poly)?;
        let t_2_commit = commit_key.commit(&t_2_poly)?;
        let t_3_commit = commit_key.commit(&t_3_poly)?;
        let t_4_commit = commit_key.commit(&t_4_poly)?;

        Ok(PreprocessedTable4Arity {
            n,
            t_1: (t_1, t_1_commit, t_1_poly),
            t_2: (t_2, t_2_commit, t_2_poly),
            t_3: (t_3, t_3_commit, t_3_poly),
            t_4: (t_4, t_4_commit, t_4_poly),
        })
    }
}
