// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Module containing the representation of a Commitment to a Polynomial.
use codec::{Decode, Encode};
use dusk_bytes::{DeserializableSlice, Serializable};
use zero_bls12_381::{G1Affine, G1Projective};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};
use zero_crypto::common::Group;

/// Holds a commitment to a polynomial in a form of a [`G1Affine`]-bls12_381
/// point.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Decode, Encode)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct Commitment(
    /// The commitment is a group element.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
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

impl Serializable<{ G1Affine::SIZE }> for Commitment {
    type Error = dusk_bytes::Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let g1 = G1Affine::from_slice(buf)?;
        Ok(Self(g1))
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

#[cfg(test)]
mod commitment_tests {
    use super::*;

    #[test]
    fn commitment_dusk_bytes_serde() {
        let commitment =
            Commitment(zero_bls12_381::G1Affine::ADDITIVE_GENERATOR);
        let bytes = commitment.to_bytes();
        let obtained_comm = Commitment::from_slice(&bytes)
            .expect("Error on the deserialization");
        assert_eq!(commitment, obtained_comm);
    }
}
