pub mod composer;
pub(crate) mod linearisation_poly;
mod preprocessed_circuit;
pub mod proof;
mod quotient_poly;

use crate::commitment_scheme::kzg10::ProverKey;
use crate::fft::EvaluationDomain;
use crate::transcript::TranscriptProtocol;

pub use composer::StandardComposer;
pub use preprocessed_circuit::PreProcessedCircuit;

/// Implementation of the standard PLONK proof system

pub trait Composer {
    // Circuit size is the amount of gates in the circuit
    fn circuit_size(&self) -> usize;
    // Preprocessing produces a preprocessed circuit
    fn preprocess(
        &mut self,
        commit_key: &ProverKey,
        transcript: &mut dyn TranscriptProtocol,
        domain: &EvaluationDomain,
    ) -> PreProcessedCircuit;
    fn prove(
        &mut self,
        commit_key: &ProverKey,
        preprocessed_circuit: &PreProcessedCircuit,
        transcript: &mut dyn TranscriptProtocol,
    ) -> proof::Proof;
}
