// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Collection of functions needed to use plonk library.
//!
//! Use this as the only import that you need to interact
//! with the principal data structures of the plonk library.
//!

pub use crate::circuit_builder::{Circuit, PublicInput};
pub use crate::commitment_scheme::kzg10::{
    key::{CommitKey, OpeningKey},
    PublicParameters,
};
pub use crate::constraint_system::{StandardComposer, Variable};
pub use crate::proof_system::{
    widget::{ProverKey, VerifierKey},
    Proof, Prover, Verifier,
};

/// Re-exported `dusk-bls12_381::BlsScalar`.
pub use dusk_bls12_381::BlsScalar;

/// Re-exported `dusk-jubjub::JubJubScalar`.
pub use dusk_jubjub::JubJubScalar;

/// Collection of errors that the library exposes/uses.
pub mod plonk_errors {
    pub use crate::error::Error;
}
