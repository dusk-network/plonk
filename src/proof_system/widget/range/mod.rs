// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod proverkey;
mod verifierkey;

pub use proverkey::ProverKey;
pub use verifierkey::{PlookupVerifierKey, VerifierKey};

/// Common functionality across both the ProverKey and VerifierKey are listed below
///
///
///
///
use dusk_bls12_381::BlsScalar;

// Computes f(f-1)(f-2)(f-3)
fn delta(f: BlsScalar) -> BlsScalar {
    let f_1 = f - BlsScalar::one();
    let f_2 = f - BlsScalar::from(2);
    let f_3 = f - BlsScalar::from(3);
    f * f_1 * f_2 * f_3
}
