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
use table::witness_table::{WitnessTable3Arity, WitnessTable4Arity};

pub struct PlookupProof3Arity {
    f: WitnessTable3Arity
    t: WitnessTable3Arity
}

pub struct PlookupProof4Arity {
    f: WitnessTable4Arity
    t: WitnessTable4Arity 
}