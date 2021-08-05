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
    circuit::{self, Circuit, PublicInputValue, VerifierData},
    commitment_scheme::kzg10::{
        key::{CommitKey, OpeningKey},
        PublicParameters,
    },
    constraint_system::{Point, StandardComposer, Variable},
    proof_system::{Proof, Prover, ProverKey, Verifier, VerifierKey},
};

/// Re-exported [`dusk-bls12_381::BlsScalar`].
pub use dusk_bls12_381::BlsScalar;

/// Re-exported [`dusk-jubjub::JubJubScalar`] &
/// [`dusk-jubjub::JubJubAffine`].
pub use dusk_jubjub::{JubJubAffine, JubJubScalar};

/// Collection of errors that the library exposes/uses.
pub use crate::error::Error;
