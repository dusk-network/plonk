// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubScalar};

const BLS_SCALAR: u8 = 1;
const JUBJUB_SCALAR: u8 = 2;
const JUBJUB_AFFINE: u8 = 3;

/// Public Input
#[derive(Debug, Copy, Clone)]
pub enum PublicInput {
    /// Scalar Input
    BlsScalar(BlsScalar, usize),
    /// Embedded Scalar Input
    JubJubScalar(JubJubScalar, usize),
    /// Point as Public Input
    AffinePoint(JubJubAffine, usize, usize),
}

impl PublicInput {
    /// Returns the serialized-size of the `PublicInput` structure.
    pub const fn serialized_size() -> usize {
        33usize
    }

    /// Returns the byte-representation of a [`PublicInput`].
    /// Note that the underlying variants of this enum have different
    /// sizes on it's byte-representation. Therefore, we need to return
    /// the biggest one to set it as the default one.
    pub fn to_bytes(&self) -> [u8; Self::serialized_size()] {
        let mut bytes = [0u8; Self::serialized_size()];
        match self {
            Self::BlsScalar(scalar, _) => {
                bytes[0] = BLS_SCALAR;
                bytes[1..33].copy_from_slice(&scalar.to_bytes());
                bytes
            }
            Self::JubJubScalar(scalar, _) => {
                bytes[0] = JUBJUB_SCALAR;
                bytes[1..33].copy_from_slice(&scalar.to_bytes());
                bytes
            }
            Self::AffinePoint(point, _, _) => {
                bytes[0] = JUBJUB_AFFINE;
                bytes[1..Self::serialized_size()].copy_from_slice(&point.to_bytes());
                bytes
            }
        }
    }

    /// Generate a [`PublicInput`] structure from it's byte representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Self::serialized_size() {
            return Err(Error::InvalidPublicInputBytes);
        } else {
            let mut array_bytes = [0u8; 32];
            array_bytes.copy_from_slice(&bytes[1..Self::serialized_size()]);
            match bytes[0] {
                BLS_SCALAR => BlsScalar::from_bytes(&array_bytes)
                    .map(|s| Self::BlsScalar(s, 0))
                    .map_err(|_| Error::InvalidPublicInputBytes),

                JUBJUB_SCALAR => JubJubScalar::from_bytes(&array_bytes)
                    .map(|s| Self::JubJubScalar(s, 0))
                    .map_err(|_| Error::InvalidPublicInputBytes),

                JUBJUB_AFFINE => JubJubAffine::from_bytes(&array_bytes)
                    .map(|s| Self::AffinePoint(s, 0, 0))
                    .map_err(|_| Error::InvalidPublicInputBytes),

                _ => unreachable!(),
            }
        }
    }

    /// Returns the positions that of a PublicInput struct
    pub(crate) fn pos(&self) -> [usize; 2] {
        match self {
            PublicInput::BlsScalar(_, pos) => [*pos, 0],
            PublicInput::JubJubScalar(_, pos) => [*pos, 0],
            PublicInput::AffinePoint(_, pos_x, pos_y) => [*pos_x, *pos_y],
        }
    }
}
