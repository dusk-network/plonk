// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

mod proverkey;
mod verifierkey;

pub use proverkey::ProverKey;
pub use verifierkey::VerifierKey;

/// Common functionality across both the ProverKey and VerifierKey are listed below
///
///
///
///
use dusk_bls12_381::Scalar;
// Computes f(f-1)(f-2)(f-3)
fn delta(f: Scalar) -> Scalar {
    let f_1 = f - Scalar::one();
    let f_2 = f - Scalar::from(2);
    let f_3 = f - Scalar::from(3);
    f * f_1 * f_2 * f_3
}

// The identity we want to check is q_logic * A = 0
// A = B + E
// B = q_c * [9c - 3(a+b)]
// E = 3(a+b+c) - 2F
// F = w[w(4w - 18(a+b) + 81) + 18(a^2 + b^2) - 81(a+b) + 83]
#[allow(non_snake_case)]
fn delta_xor_and(a: &Scalar, b: &Scalar, w: &Scalar, c: &Scalar, q_c: &Scalar) -> Scalar {
    let nine = Scalar::from(9);
    let two = Scalar::from(2);
    let three = Scalar::from(3);
    let four = Scalar::from(4);
    let eighteen = Scalar::from(18);
    let eighty_one = Scalar::from(81);
    let eighty_three = Scalar::from(83);

    let F = w
        * (w * (four * w - eighteen * (a + b) + eighty_one) + eighteen * (a.square() + b.square())
            - eighty_one * (a + b)
            + eighty_three);
    let E = three * (a + b + c) - (two * F);
    let B = q_c * ((nine * c) - three * (a + b));
    B + E
}
