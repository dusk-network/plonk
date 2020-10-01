// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

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
