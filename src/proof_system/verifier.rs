// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::kzg10::{CommitKey, OpeningKey};
use crate::constraint_system::{PlookupComposer, StandardComposer};
use crate::plookup::{MultiSet, PlookupTable4Arity, PreprocessedTable4Arity};
use crate::proof_system::widget::{PlookupVerifierKey, VerifierKey};
use crate::proof_system::{PlookupProof, Proof};
use anyhow::{Error, Result};
use dusk_bls12_381::BlsScalar;
use merlin::Transcript;

/// Verifier verifies a proof
#[allow(missing_debug_implementations)]
pub struct Verifier {
    /// VerificationKey which is used to verify a specific PLONK circuit
    pub verifier_key: Option<VerifierKey>,

    pub(crate) cs: StandardComposer,
    /// Store the messages exchanged during the preprocessing stage
    /// This is copied each time, we make a proof, so that we can use the same verifier to
    /// Verify multiple proofs from the same circuit. If this is not copied, then the verification procedure will modify
    /// the transcript, making it unusable for future proofs.
    pub preprocessed_transcript: Transcript,
}

impl Default for Verifier {
    fn default() -> Verifier {
        Verifier::new(b"plonk")
    }
}

impl Verifier {
    /// Creates a new verifier object
    pub fn new(label: &'static [u8]) -> Verifier {
        Verifier {
            verifier_key: None,
            cs: StandardComposer::new(),
            preprocessed_transcript: Transcript::new(label),
        }
    }

    /// Creates a new verifier object with some expected size.
    pub fn with_expected_size(label: &'static [u8], size: usize) -> Verifier {
        Verifier {
            verifier_key: None,
            cs: StandardComposer::with_expected_size(size),
            preprocessed_transcript: Transcript::new(label),
        }
    }

    /// Returns the number of gates in the circuit
    pub fn circuit_size(&self) -> usize {
        self.cs.circuit_size()
    }

    /// Returns a mutable copy of the underlying composer
    pub fn mut_cs(&mut self) -> &mut StandardComposer {
        &mut self.cs
    }

    /// Preprocess a proof
    pub fn preprocess(&mut self, commit_key: &CommitKey) -> Result<(), Error> {
        let vk = self
            .cs
            .preprocess_verifier(commit_key, &mut self.preprocessed_transcript)?;

        self.verifier_key = Some(vk);
        Ok(())
    }

    /// Keys the transcript with additional seed information
    /// Wrapper around transcript.append_message
    pub fn key_transcript(&mut self, label: &'static [u8], message: &[u8]) {
        self.preprocessed_transcript.append_message(label, message);
    }

    /// Verifies a proof
    pub fn verify(
        &self,
        proof: &Proof,
        opening_key: &OpeningKey,
        public_inputs: &[BlsScalar],
    ) -> Result<(), Error> {
        let mut cloned_transcript = self.preprocessed_transcript.clone();
        let verifier_key = self.verifier_key.as_ref().unwrap();

        proof.verify(
            verifier_key,
            &mut cloned_transcript,
            opening_key,
            public_inputs,
        )
    }
}

/// Verifier verifies a plookup proof
#[allow(missing_debug_implementations)]
pub struct PlookupVerifier {
    /// VerificationKey which is used to verify a specific Plookup circuit
    pub verifier_key: Option<PlookupVerifierKey>,

    pub(crate) cs: PlookupComposer,
    /// Store the messages exchanged during the preprocessing stage
    /// This is copied each time, we make a proof, so that we can use the same verifier to
    /// Verify multiple proofs from the same circuit. If this is not copied, then the verification procedure will modify
    /// the transcript, making it unusable for future proofs.
    pub preprocessed_transcript: Transcript,
}

impl Default for PlookupVerifier {
    fn default() -> PlookupVerifier {
        PlookupVerifier::new(b"plookup")
    }
}

impl PlookupVerifier {
    /// Creates a new verifier object
    pub fn new(label: &'static [u8]) -> PlookupVerifier {
        PlookupVerifier {
            verifier_key: None,
            cs: PlookupComposer::new(),
            preprocessed_transcript: Transcript::new(label),
        }
    }

    /// Creates a new verifier object with some expected size.
    pub fn with_expected_size(label: &'static [u8], size: usize) -> PlookupVerifier {
        PlookupVerifier {
            verifier_key: None,
            cs: PlookupComposer::with_expected_size(size),
            preprocessed_transcript: Transcript::new(label),
        }
    }

    /// Returns the number of gates in the circuit
    pub fn circuit_size(&self) -> usize {
        self.cs.circuit_size()
    }

    /// Returns a mutable copy of the underlying composer
    pub fn mut_cs(&mut self) -> &mut PlookupComposer {
        &mut self.cs
    }

    /// Preprocess a proof
    pub fn preprocess(&mut self, commit_key: &CommitKey) -> Result<(), Error> {
        let vk = self
            .cs
            .preprocess_verifier(commit_key, &mut self.preprocessed_transcript)?;

        self.verifier_key = Some(vk);
        Ok(())
    }

    /// Keys the transcript with additional seed information
    /// Wrapper around transcript.append_message
    pub fn key_transcript(&mut self, label: &'static [u8], message: &[u8]) {
        self.preprocessed_transcript.append_message(label, message);
    }

    /// Verifies a proof
    pub fn verify(
        &self,
        proof: &PlookupProof,
        opening_key: &OpeningKey,
        public_inputs: &[BlsScalar],
        lookup_table: &PlookupTable4Arity,
    ) -> Result<(), Error> {
        let mut cloned_transcript = self.preprocessed_transcript.clone();
        let verifier_key = self.verifier_key.as_ref().unwrap();

        proof.verify(
            verifier_key,
            &mut cloned_transcript,
            opening_key,
            lookup_table,
            public_inputs,
        )
    }
}
