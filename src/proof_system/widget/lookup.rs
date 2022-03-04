// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
mod proverkey;
mod verifierkey;

#[cfg(feature = "alloc")]
pub use proverkey::ProverKey;
pub use verifierkey::VerifierKey;

// Common functionality across both the ProverKey and VerifierKey is
// enacted below
#[cfg(feature = "alloc")]
use dusk_bls12_381::BlsScalar;

#[cfg(feature = "alloc")]
fn compress(
    a_w: BlsScalar,
    b_w: BlsScalar,
    c_w: BlsScalar,
    d_w: BlsScalar,
    zeta: BlsScalar,
) -> BlsScalar {
    let zeta_sq = zeta.square();
    let zeta_cu = zeta_sq * zeta;

    let a = a_w;

    let b = b_w * zeta;

    let c = c_w * zeta_sq;

    let d = d_w * zeta_cu;

    a + b + c + d
}
