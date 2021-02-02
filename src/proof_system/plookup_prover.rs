// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::proof_system_errors::ProofErrors;
use crate::commitment_scheme::kzg10::CommitKey;
use crate::constraint_system::{PlookupComposer, Variable};
use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::widget::ProverKey;
use crate::proof_system::{linearisation_poly, proof::Proof, quotient_poly};
use crate::transcript::TranscriptProtocol;
use anyhow::{Error, Result};
use dusk_bls12_381::BlsScalar;
use merlin::Transcript;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

/// Prover composes a circuit and builds a proof
#[allow(missing_debug_implementations)]
pub struct PlookupProver {
    /// ProverKey which is used to create proofs about a specific PLONK circuit
    pub prover_key: Option<ProverKey>,

    pub(crate) cs: PlookupComposer,
    /// Store the messages exchanged during the preprocessing stage
    /// This is copied each time, we make a proof
    pub preprocessed_transcript: Transcript,
}

impl PlookupProver {
    /// Returns a mutable copy of the underlying composer
    pub fn mut_cs(&mut self) -> &mut PlookupComposer {
        &mut self.cs
    }
    /// Preprocesses the underlying constraint system
    pub fn preprocess(&mut self, commit_key: &CommitKey) -> Result<(), Error> {
        if self.prover_key.is_some() {
            return Err(ProofErrors::CircuitAlreadyPreprocessed.into());
        }
        let pk = self
            .cs
            .preprocess_prover(commit_key, &mut self.preprocessed_transcript)?;
        self.prover_key = Some(pk);
        Ok(())
    }
}

impl Default for PlookupProver {
    fn default() -> PlookupProver {
        PlookupProver::new(b"plookup")
    }
}

impl PlookupProver {
    /// Creates a new prover object
    pub fn new(label: &'static [u8]) -> PlookupProver {
        PlookupProver {
            prover_key: None,
            cs: PlookupComposer::new(),
            preprocessed_transcript: Transcript::new(label),
        }
    }

     /// Creates a new prover object with some expected size.
    pub fn with_expected_size(label: &'static [u8], size: usize) -> PlookupProver {
        PlookupProver {
            prover_key: None,
            cs: PlookupComposer::with_expected_size(size),
            preprocessed_transcript: Transcript::new(label),
        }
    }
}