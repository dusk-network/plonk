mod composer;
mod constraint_system;
mod permutation;

use algebra::curves::PairingEngine;
use poly_commit::kzg10::Commitment;

use crate::transcript::TranscriptProtocol;
use ff_fft::EvaluationDomain;
use poly_commit::kzg10::UniversalParams;

// Preprocessed cirucit includes the commitment to the selector polynomials and the simga polynomials
pub struct PreProcessedCircuit<E: PairingEngine> {
    selector_polys: Vec<Commitment<E>>,
    left_sigma_poly: Commitment<E>,
    right_sigma_poly: Commitment<E>,
    out_sigma_poly: Commitment<E>,
}

// Empty proof struct that for now, will only be used for the Composer trait
pub struct Proof {}

pub trait Composer<E: PairingEngine> {
    // Circuit size is the amount of gates in the circuit
    fn circuit_size(&self) -> usize;
    // Preprocessing produces a preprocessed circuit
    fn preprocess(
        &mut self,
        public_parameters: &UniversalParams<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        domain: &EvaluationDomain<E::Fr>,
    ) -> PreProcessedCircuit<E>;
    // Prove creates a proof by preprocessing the circuit first and computing the necessary polynomials
    // N.B. We could pass a `PreprocessedCircuit` into `Prove` however, we must ensure that it contains
    // enough state to build the rest of the proof. We can do this by adding the necessary polynomials into the
    // preprocessed circuit along with their commitments and size of circuit, etc
    fn prove(
        &mut self,
        public_parameters: &UniversalParams<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
    ) -> Proof;
}