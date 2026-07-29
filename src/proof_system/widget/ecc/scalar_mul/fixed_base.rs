// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
pub(crate) mod proverkey;

mod verifierkey;

#[cfg(feature = "alloc")]
pub(crate) use proverkey::ProverKey;
pub(crate) use verifierkey::VerifierKey;

// Note: The ECC gadget does not check that the initial point is on the curve
// for two reasons:
// - We constrain the accumulator to start from the identity point, which the
//   verifier knows is on the curve
// - We are adding multiples of the generator to the accumulator.
//   `Composer::component_mul_generator` rejects generators that are not
//   on-curve points of exact prime order before emitting these gates.
// - We do allow arbitrary BlsScalar multiplication; the composer separately
//   constrains it to the canonical Jubjub scalar interval.

// Bits are accumulated in base2. So we use d(Xw) - 2d(X) to extract the base2
// bit
