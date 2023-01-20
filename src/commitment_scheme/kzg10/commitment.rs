// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Module containing the representation of a Commitment to a Polynomial.
use codec::{Decode, Encode};
use zero_bls12_381::{G1Affine, G1Projective};

/// Holds a commitment to a polynomial in a form of a [`G1Affine`]-bls12_381
/// point.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Decode, Encode)]
pub(crate) struct Commitment(
    /// The commitment is a group element.
    pub(crate) G1Affine,
);

impl From<G1Affine> for Commitment {
    fn from(point: G1Affine) -> Commitment {
        Commitment(point)
    }
}

impl From<G1Projective> for Commitment {
    fn from(point: G1Projective) -> Commitment {
        Commitment(point.into())
    }
}

impl Commitment {
    /// Builds an identity [`Commitment`] which is equivalent to the
    /// [`G1Affine`] identity point in bls12_381.
    fn identity() -> Commitment {
        Commitment(G1Affine::ADDITIVE_IDENTITY)
    }
}

impl Default for Commitment {
    fn default() -> Commitment {
        Commitment::identity()
    }
}
