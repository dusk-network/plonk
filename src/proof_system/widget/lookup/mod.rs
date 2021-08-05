// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
mod proverkey;
#[cfg(feature = "alloc")]
mod verifierkey;

#[cfg(feature = "alloc")]
pub use proverkey::ProverKey;
#[cfg(feature = "alloc")]
pub use verifierkey::VerifierKey;

/// Common functionality across both the ProverKey and VerifierKey is
/// enacted below
use dusk_bls12_381::BlsScalar;

fn compress(
    w_l: BlsScalar,
    w_r: BlsScalar,
    w_o: BlsScalar,
    w_4: BlsScalar,
    zeta: BlsScalar,
) -> BlsScalar {
    let zeta_sq = zeta.square();
    let zeta_cu = zeta_sq * zeta;

    let a = w_l;

    let b = w_r * zeta;

    let c = w_o * zeta_sq;

    let d = w_4 * zeta_cu;

    a + b + c + d
}
