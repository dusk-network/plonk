mod composer;
mod constraint_system;
mod linearisation;
mod opening;
mod permutation;
mod proof;
mod quotient_poly;

use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::DensePolynomial as Polynomial;
use poly_commit::kzg10::Commitment;

use crate::transcript::TranscriptProtocol;
use ff_fft::EvaluationDomain;
use poly_commit::kzg10::Powers;
use rand_core::{CryptoRng, RngCore};

// Preprocessed cirucit includes the commitment to the selector polynomials and the sigma polynomials
pub struct PreProcessedCircuit<E: PairingEngine> {
    // The number of gates in the circuit
    n: usize,
    // Selector polynomial coefficients q_m, q_l, q_r, q_o, q_c and their commitments
    selectors: Vec<(Vec<E::Fr>, Commitment<E>)>,

    // Sigma polynomials and their commitments
    left_sigma: (Vec<E::Fr>, Commitment<E>),
    right_sigma: (Vec<E::Fr>, Commitment<E>),
    out_sigma: (Vec<E::Fr>, Commitment<E>),
}
impl<E: PairingEngine> PreProcessedCircuit<E> {
    pub fn qm_poly(&self) -> &[E::Fr] {
        &self.selectors[0].0
    }
    pub fn ql_poly(&self) -> &[E::Fr] {
        &self.selectors[1].0
    }
    pub fn qr_poly(&self) -> &[E::Fr] {
        &self.selectors[2].0
    }
    pub fn qo_poly(&self) -> &[E::Fr] {
        &self.selectors[3].0
    }
    pub fn qc_poly(&self) -> &[E::Fr] {
        &self.selectors[4].0
    }
    pub fn left_sigma_poly(&self) -> &[E::Fr] {
        &self.left_sigma.0
    }
    pub fn right_sigma_poly(&self) -> &[E::Fr] {
        &self.right_sigma.0
    }
    pub fn out_sigma_poly(&self) -> &[E::Fr] {
        &self.out_sigma.0
    }
    pub fn qm_comm(&self) -> &Commitment<E> {
        &self.selectors[0].1
    }
    pub fn ql_comm(&self) -> &Commitment<E> {
        &self.selectors[1].1
    }
    pub fn qr_comm(&self) -> &Commitment<E> {
        &self.selectors[2].1
    }
    pub fn qo_comm(&self) -> &Commitment<E> {
        &self.selectors[3].1
    }
    pub fn qc_comm(&self) -> &Commitment<E> {
        &self.selectors[4].1
    }
    pub fn left_sigma_comm(&self) -> &Commitment<E> {
        &self.left_sigma.1
    }
    pub fn right_sigma_comm(&self) -> &Commitment<E> {
        &self.right_sigma.1
    }
    pub fn out_sigma_comm(&self) -> &Commitment<E> {
        &self.out_sigma.1
    }
}

pub trait Composer<E: PairingEngine> {
    // Circuit size is the amount of gates in the circuit
    fn circuit_size(&self) -> usize;
    // Preprocessing produces a preprocessed circuit
    fn preprocess(
        &mut self,
        commit_key: &Powers<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        domain: &EvaluationDomain<E::Fr>,
    ) -> PreProcessedCircuit<E>;
    fn prove<R: RngCore + CryptoRng>(
        &mut self,
        commit_key: &Powers<E>,
        preprocessed_circuit: &PreProcessedCircuit<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        rng: &mut R,
    ) -> proof::Proof<E>;
}
