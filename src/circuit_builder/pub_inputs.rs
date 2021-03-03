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

/// Trait that all of the structures that can be used as Public Inputs for a [`super::Circuit`]
/// should implement.
pub trait PublicInput<const N: usize>: Copy + Serializable<N> {
    const PI_SIZE: usize = N;
    /// XXX
    fn value(&self) -> Vec<BlsScalar>;
    /// XXX
    fn to_pi_bytes(&self) -> [u8; N] {
        self.value().iter().flat_map(|val| val.to_bytes()).collect()
    }
    /// XXX
    fn from_pi_bytes(bytes: &[u8; N]) -> Result<Vec<BlsScalar>, Error> {
        bytes
            .chunks(BlsScalar::SIZE)
            .map(|chunk| BlsScalar::from_bytes(chunk))
            .collect()
    }
}

impl PublicInput<{ BlsScalar::SIZE }> for BlsScalar {
    fn value(self) -> Vec<BlsScalar> {
        vec![self]
    }
}

impl PublicInput<{ BlsScalar::SIZE }> for JubJubScalar {
    fn value(self) -> Vec<BlsScalar> {
        vec![self.into()]
    }
}

impl PublicInput<{ BlsScalar::SIZE * 2 }> for JubJubAffine {
    fn value(self) -> Vec<BlsScalar> {
        vec![self.get_x(), self.get_y()]
    }
}
