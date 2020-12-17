// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

// use crate::multiset::MultiSet;
// use crate::table::lookup_table::{PlookupTable3Arity, PlookupTable4Arity};
// use crate::table::preprocess::{PreprocessedTable3Arity, PreprocessedTable4Arity};
// use crate::table::witness_table::{WitnessTable3Arity, WitnessTable4Arity};
// use anyhow::{Error, Result};
// use dusk_plonk::bls12_381::{BlsScalar, G1Affine};
// use dusk_plonk::commitment_scheme::kzg10;
// use dusk_plonk::commitment_scheme::kzg10::{CommitKey, Commitment};
// use dusk_plonk::fft::{EvaluationDomain, Polynomial};
// use crate::multiset::compress_four_arity;
// use dusk_plonk::proof_system::ProverKey;
// use merlin::Transcript;

// XXX: To be dealt with within plookup_gate PR.

// pub struct PlookupProof3Arity {
//     f: WitnessTable3Arity,
//     t: PreprocessedTable3Arity,
// }

// pub struct PlookupProof4Arity {
//     f: WitnessTable4Arity,
//     t: PreprocessedTable4Arity,
//     proving_key: ProverKey,
//     transcript: &'a mut dyn TranscriptProtocol,
// }

// impl PlookupProof4Arity {
//     pub fn create_proof(
//         f: WitnessTable4Arity,
//         t: PreprocessedTable4Arity,
//         proving_key: ProverKey,
//         transcript: &'a mut dyn TranscriptProtocol,
//     ) -> PlookupProof4Arity {
//         let alpha = BlsScalar::from(15u64);
//         let f_set = compress_four_arity(f, alpha);
//         let t_set = compress_four_arity(t, alpha);

//         let s = t_set.sort_and_index(f_set);
//         let (h_1, h_2) = s.halve();
//         unimplemented!()
//     }
// }
