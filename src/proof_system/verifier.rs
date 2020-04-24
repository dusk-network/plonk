use crate::commitment_scheme::kzg10::{ProverKey, VerifierKey};
use crate::constraint_system::StandardComposer;
use crate::proof_system::PreProcessedCircuit;
use crate::proof_system::Proof;
use bls12_381::Scalar;
use merlin::Transcript;

/// Verifier verifies a proof
#[allow(missing_debug_implementations)]
pub struct Verifier {
    /// Preprocessed circuit
    pub preprocessed_circuit: Option<PreProcessedCircuit>,

    pub(crate) cs: StandardComposer,
    /// Store the messages exchanged during the preprocessing stage
    /// This is copied each time, we make a proof
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
            preprocessed_circuit: None,
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
    pub fn preprocess(&mut self, commit_key: &ProverKey) {
        let ppc = self
            .cs
            .preprocess(commit_key, &mut self.preprocessed_transcript);

        self.preprocessed_circuit = Some(ppc)
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
