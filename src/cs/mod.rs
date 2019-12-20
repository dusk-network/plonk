mod composer;
mod constraint_system;
mod linearisation;
mod opening;
mod permutation;
mod proof;
mod quotient_poly;

use algebra::curves::PairingEngine;
use ff_fft::DensePolynomial as Polynomial;
use poly_commit::kzg10::Commitment;

use crate::transcript::TranscriptProtocol;
use ff_fft::EvaluationDomain;
use poly_commit::kzg10::UniversalParams;
use rand_core::{CryptoRng, RngCore};

// Preprocessed cirucit includes the commitment to the selector polynomials and the sigma polynomials
pub struct PreProcessedCircuit<E: PairingEngine> {
    // Returns the selector polynomials q_m, q_l, q_r, q_o, q_c, other custom polynomials
    selector_polys: Vec<(Polynomial<E::Fr>, Commitment<E>)>,

    // Returns the permutation polynomials
    left_sigma_poly: (Polynomial<E::Fr>, Commitment<E>),
    right_sigma_poly: (Polynomial<E::Fr>, Commitment<E>),
    out_sigma_poly: (Polynomial<E::Fr>, Commitment<E>),
}
impl<E: PairingEngine> PreProcessedCircuit<E> {
    pub fn qm_poly(&self) -> &Polynomial<E::Fr> {
        &self.selector_polys[0].0
    }
    pub fn ql_poly(&self) -> &Polynomial<E::Fr> {
        &self.selector_polys[1].0
    }
    pub fn qr_poly(&self) -> &Polynomial<E::Fr> {
        &self.selector_polys[2].0
    }
    pub fn qo_poly(&self) -> &Polynomial<E::Fr> {
        &self.selector_polys[3].0
    }
    pub fn qc_poly(&self) -> &Polynomial<E::Fr> {
        &self.selector_polys[4].0
    }
}

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
    fn prove<R: RngCore + CryptoRng>(
        &mut self,
        public_parameters: &UniversalParams<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        rng: &mut R,
    ) -> proof::Proof<E>;
}
