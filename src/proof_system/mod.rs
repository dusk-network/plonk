// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! proving system

pub(crate) mod linearisation_poly;
mod preprocess;

pub(crate) mod lookup_quotient;

pub(crate) mod lookup_lineariser;
mod plookup_preprocess;

/// Represents PLONK Proof
pub mod proof;
pub(crate) mod proof_system_errors;

/// Represents a plookup proofs
pub mod plookup_proof;

/// Represents a PLONK Prover
pub mod prover;
pub(crate) mod quotient_poly;
/// Represents a PLONK Verifier
pub mod verifier;
pub(crate) mod widget;

/// Represents a Plookup Verifier
pub mod plookup_verifier;

pub use plookup_proof::PlookupProof;
pub use plookup_verifier::PlookupVerifier;
pub use proof::Proof;
pub use prover::{PlookupProver, Prover};
pub use verifier::Verifier;
pub use widget::{PlookupProverKey, PlookupVerifierKey, ProverKey, VerifierKey};
