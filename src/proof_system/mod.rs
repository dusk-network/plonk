// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

//! proving system

pub(crate) mod linearisation_poly;
mod preprocess;

/// Represents a PLONK Proof
pub mod proof;
pub(crate) mod proof_system_errors;
/// Represents a PLONK Prover
pub mod prover;
pub(crate) mod quotient_poly;
/// Represents a PLONK Verifier
pub mod verifier;
pub(crate) mod widget;

pub use proof::Proof;
pub use prover::Prover;
pub use verifier::Verifier;
