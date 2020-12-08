// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use anyhow::{Error, Result};
use dusk_plonk::commitment_scheme::kzg10;
use crate::multiset::MultiSet;
use crate::table::lookup_table::{PlookupTable3Arity, PlookupTable4Arity};
use dusk_plonk::bls12_381::{BlsScalar, G1Affine};
use dusk_plonk::commitment_scheme::kzg10::{CommitKey, Commitment};
use dusk_plonk::fft::{EvaluationDomain, Polynomial};
use crate::table::witness_table::{WitnessTable3Arity, WitnessTable4Arity};

pub struct PlookupProof3Arity {
    f: WitnessTable3Arity,
    t: WitnessTable3Arity,
}

pub struct PlookupProof4Arity {
    f: WitnessTable4Arity,
    t: WitnessTable4Arity,
}
