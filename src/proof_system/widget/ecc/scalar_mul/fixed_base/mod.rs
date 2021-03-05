// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod proverkey;
mod verifierkey;

pub(crate) use proverkey::ProverKey;
pub(crate) use verifierkey::VerifierKey;

// Note: The ECC gadget does not check that the initial point is on the curve for two reasons:
// - We constrain the accumulator to start from the identity point, which the verifier knows is on the curve
// - We are adding multiples of the generator to the accumulator which the verifier also knows is on the curve and is prime order
// - We do allow arbitrary BlsScalar multiplication, and possibly XXX: may add constraints to ensure the generator is correct (prime order)

// Bits are accumulated in base2. So we use d(Xw) - 2d(X) to extract the base2 bit

use dusk_bls12_381::BlsScalar;
fn extract_bit(curr_acc: &BlsScalar, next_acc: &BlsScalar) -> BlsScalar {
    // Next - 2 * current
    next_acc - (curr_acc + curr_acc)
}

// Ensures that the bit is either +1, -1 or 0
fn check_bit_consistency(bit: BlsScalar) -> BlsScalar {
    let one = BlsScalar::one();
    bit * (bit - one) * (bit + one)
}
