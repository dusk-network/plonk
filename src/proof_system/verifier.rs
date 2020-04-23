use crate::commitment_scheme::kzg10::{ProverKey, VerifierKey};
use crate::constraint_system::StandardComposer;
use crate::proof_system::PreProcessedCircuit;
use crate::proof_system::Proof;
use bls12_381::Scalar;
use merlin::Transcript;

/// Verifier verifies a proof
#[allow(missing_debug_implementations)]
pub struct Verifier {
    pub(crate) preprocessed_circuit: Option<PreProcessedCircuit>,

    pub(crate) cs: StandardComposer,
    // Store the messages exchanged during the preprocessing stage
    // This is copied each time, we make a proof
    pub(crate) preprocessed_transcript: Transcript,
}

impl Default for Verifier {
    fn default() -> Verifier {
        Verifier::new()
    }
}

impl Verifier {
    /// Creates a new verifier object
    pub fn new() -> Verifier {
        Verifier {
            preprocessed_circuit: None,
            cs: StandardComposer::new(),
            preprocessed_transcript: Transcript::new(b"plonk"),
        }
    }

    /// Returns a mutable copy of the underlying composer
    pub fn mut_cs(&mut self) -> &mut StandardComposer {
        &mut self.cs
    }
    /// Preprocess a proof
    pub fn preprocess(&mut self, commit_key: &ProverKey) {
        let ppc = self
            .cs
            .preprocess(commit_key, &mut self.preprocessed_transcript);

        self.preprocessed_circuit = Some(ppc)
    }
    /// Verifies a proof
    pub fn verify(
        &self,
        proof: &Proof,
        verifier_key: &VerifierKey,
        public_inputs: &[Scalar],
    ) -> bool {
        let mut cloned_transcript = self.preprocessed_transcript.clone();
        let preprocessed_circuit = self.preprocessed_circuit.as_ref().unwrap();

        proof.verify(
            preprocessed_circuit,
            &mut cloned_transcript,
            verifier_key,
            public_inputs,
        )
    }
}
