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

use super::{Composer, Constraint, WireData};

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

/// Both gates that read a witness must have their wires linked into one cycle
/// of the copy permutation. The permutation argument enforces that cycle, so
/// without it the two gates could read different values.
#[test]
fn gates_reading_one_witness_share_a_permutation_cycle() {
    let mut composer = Composer::initialized();
    let x = composer.append_witness(BlsScalar::from(7u64));

    let first = composer.constraints();
    composer.append_gate(Constraint::new().a(x));
    let second = composer.constraints();
    composer.append_gate(Constraint::new().b(x));

    let n = composer.constraints();
    let [left, right, _, _] = composer.perm.compute_sigma_permutations(n);
    assert_eq!(left[first], WireData::Right(second));
    assert_eq!(right[second], WireData::Left(first));
}
