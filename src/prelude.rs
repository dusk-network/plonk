// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Collection of functions needed to use plonk library.
//!
//! Use this as the only import that you need to interact
//! with the principal data structures of the plonk library.

#[cfg(feature = "alloc")]
pub use crate::{
    commitment_scheme::PublicParameters,
    composer::{Builder, Circuit, Compiler, Composer, Prover, Verifier},
    constraint_system::{Constraint, Witness, WitnessPoint},
};

pub use crate::error::Error;
pub use crate::proof_system::Proof;
pub use dusk_bls12_381::BlsScalar;
pub use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
