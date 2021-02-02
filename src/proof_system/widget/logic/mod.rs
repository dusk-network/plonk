// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod proverkey;
mod verifierkey;

pub use proverkey::ProverKey;
pub use verifierkey::{VerifierKey, PlookupVerifierKey};

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

// The identity we want to check is q_logic * A = 0
// A = B + E
// B = q_c * [9c - 3(a+b)]
// E = 3(a+b+c) - 2F
// F = w[w(4w - 18(a+b) + 81) + 18(a^2 + b^2) - 81(a+b) + 83]
#[allow(non_snake_case)]
fn delta_xor_and(
    a: &BlsScalar,
    b: &BlsScalar,
    w: &BlsScalar,
    c: &BlsScalar,
    q_c: &BlsScalar,
) -> BlsScalar {
    let nine = BlsScalar::from(9);
    let two = BlsScalar::from(2);
    let three = BlsScalar::from(3);
    let four = BlsScalar::from(4);
    let eighteen = BlsScalar::from(18);
    let eighty_one = BlsScalar::from(81);
    let eighty_three = BlsScalar::from(83);

    let F = w
        * (w * (four * w - eighteen * (a + b) + eighty_one) + eighteen * (a.square() + b.square())
            - eighty_one * (a + b)
            + eighty_three);
    let E = three * (a + b + c) - (two * F);
    let B = q_c * ((nine * c) - three * (a + b));
    B + E
}
