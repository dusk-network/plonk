// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubScalar};

pub(crate) const BLS_SCALAR: u8 = 1;
pub(crate) const JUBJUB_SCALAR: u8 = 2;
pub(crate) const JUBJUB_AFFINE: u8 = 3;

/*trait PublicInput {
    fn value() -> &[BlsScalar];
    fn to_pi_bytes() ->
}*/

/// Public Input Values
#[derive(Debug, Copy, Clone)]
pub enum PublicInputValue {
    /// Scalar.
    BlsScalar(BlsScalar),
    /// Embedded Scalar.
    JubJubScalar(JubJubScalar),
    /// Point.
    AffinePoint(JubJubAffine),
}

impl PublicInputValue {
    /// Returns the serialized-size of the `PublicInputValue` structure.
    pub const fn serialized_size() -> usize {
        33usize
    }

    /// Returns the byte-representation of a [`PublicInputValue`].
    /// Note that the underlying variants of this enum have different
    /// sizes on it's byte-representation. Therefore, we need to return
    /// the biggest one to set it as the default one.
    pub fn to_bytes(&self) -> [u8; Self::serialized_size()] {
        let mut bytes = [0u8; Self::serialized_size()];
        match self {
            Self::BlsScalar(scalar) => {
                bytes[0] = BLS_SCALAR;
                bytes[1..33].copy_from_slice(&scalar.to_bytes());
                bytes
            }
            Self::JubJubScalar(scalar) => {
                bytes[0] = JUBJUB_SCALAR;
                bytes[1..33].copy_from_slice(&scalar.to_bytes());
                bytes
            }
            Self::AffinePoint(point) => {
                bytes[0] = JUBJUB_AFFINE;
                bytes[1..Self::serialized_size()].copy_from_slice(&point.to_bytes());
                bytes
            }
        }
    }

    /// Generate a [`PublicInputValue`] structure from it's byte representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Self::serialized_size() {
            return Err(Error::InvalidPublicInputBytes);
        } else {
            let mut array_bytes = [0u8; 32];
            array_bytes.copy_from_slice(&bytes[1..Self::serialized_size()]);
            match bytes[0] {
                BLS_SCALAR => BlsScalar::from_bytes(&array_bytes)
                    .map(|s| Self::BlsScalar(s))
                    .map_err(|_| Error::InvalidPublicInputBytes),

                JUBJUB_SCALAR => JubJubScalar::from_bytes(&array_bytes)
                    .map(|s| Self::JubJubScalar(s))
                    .map_err(|_| Error::InvalidPublicInputBytes),

                JUBJUB_AFFINE => JubJubAffine::from_bytes(&array_bytes)
                    .map(|s| Self::AffinePoint(s))
                    .map_err(|_| Error::InvalidPublicInputBytes),

                _ => unreachable!(),
            }
        }
    }
}

/// Public Input Positions
#[derive(Default, Debug, Clone)]
pub struct PublicInputPositions(pub(crate) Vec<usize>);
