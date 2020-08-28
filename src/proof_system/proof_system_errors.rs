// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

//! Errors related to the proof_system module.

use thiserror::Error;

/// Defines all of the possible ProofError types that we could have when
/// we are working with the `proof_system` module.
#[derive(Error, Debug)]
pub enum ProofErrors {
    /// This error occurs when the verification of a `Proof` fails.
    #[error("proof verification failed")]
    ProofVerificationError,
    /// This error occurrs when the Prover structure already contains a
    /// preprocessed circuit inside, but you call preprocess again.
    #[error("circuit already preprocessed")]
    CircuitAlreadyPreprocessed,
}
