// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

use crate::commitment_scheme::kzg10::{CommitKey, OpeningKey};
use crate::constraint_system::StandardComposer;
use crate::proof_system::widget::VerifierKey;
use crate::proof_system::Proof;
use anyhow::{Error, Result};
use dusk_bls12_381::Scalar;
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
        public_inputs: &[Scalar],
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
