// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! In-crate tests for the composer.
//!
//! These reach composer internals that are not part of the public API, so they
//! live here rather than in the crate-root `tests/` directory.

use dusk_bls12_381::BlsScalar;

mod soundness;

#[test]
fn minus_one_keeps_its_previous_limbs() {
    // Montgomery limbs of the hand-written constant `MINUS_ONE` replaced.
    const PREVIOUS: [u64; 4] = [
        0xfffffffd00000003,
        0xfb38ec08fffb13fc,
        0x99ad88181ce5880f,
        0x5bc8f5f97cd877d8,
    ];

    assert_eq!(super::MINUS_ONE.internal_repr(), &PREVIOUS);
    assert_eq!(super::MINUS_ONE, -BlsScalar::one());
}
