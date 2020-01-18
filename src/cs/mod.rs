mod composer;
mod constraint_system;
mod linearisation;
mod opening;
mod permutation;
mod proof;
mod public_inputs;
mod quotient_poly;

use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::DensePolynomial as Polynomial;
use poly_commit::kzg10::Commitment;

use crate::transcript::TranscriptProtocol;
use ff_fft::EvaluationDomain;
use poly_commit::kzg10::UniversalParams;
use rand_core::{CryptoRng, RngCore};

// Preprocessed cirucit includes the commitment to the selector polynomials and the sigma polynomials
pub struct PreProcessedCircuit<E: PairingEngine> {
    // The number of gates in the circuit
    n: usize,
    // Selector polynomials q_m, q_l, q_r, q_o, q_c and their commitments
    selectors: Vec<(Polynomial<E::Fr>, Commitment<E>)>,

    // Sigma polynomials and their commitments
    left_sigma: (Polynomial<E::Fr>, Commitment<E>),
    right_sigma: (Polynomial<E::Fr>, Commitment<E>),
    out_sigma: (Polynomial<E::Fr>, Commitment<E>),
}
impl<E: PairingEngine> PreProcessedCircuit<E> {
    pub fn qm_poly(&self) -> &Polynomial<E::Fr> {
        &self.selectors[0].0
    }
    pub fn ql_poly(&self) -> &Polynomial<E::Fr> {
        &self.selectors[1].0
    }
    pub fn qr_poly(&self) -> &Polynomial<E::Fr> {
        &self.selectors[2].0
    }
    pub fn qo_poly(&self) -> &Polynomial<E::Fr> {
        &self.selectors[3].0
    }
    pub fn qc_poly(&self) -> &Polynomial<E::Fr> {
        &self.selectors[4].0
    }
    pub fn left_sigma_poly(&self) -> &Polynomial<E::Fr> {
        &self.left_sigma.0
    }
    pub fn right_sigma_poly(&self) -> &Polynomial<E::Fr> {
        &self.right_sigma.0
    }
    pub fn out_sigma_poly(&self) -> &Polynomial<E::Fr> {
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

    pub fn compute_n_lagrange_polys(&self) -> Vec<Polynomial<E::Fr>> {
        use ff_fft::{DenseOrSparsePolynomial, SparsePolynomial};
        use std::str::FromStr;
        let n = self.qm_poly().len();
        // Compute the denominator.
        // TODO: What should we do with the constant `Cx`?
        let numerator: DenseOrSparsePolynomial<E::Fr> =
            SparsePolynomial::from_coefficients_slice(&[(0, -E::Fr::one()), (n, E::Fr::one())])
                .into();

        let denoninators: Vec<DenseOrSparsePolynomial<E::Fr>> = {
            let mut den: Vec<DenseOrSparsePolynomial<E::Fr>> = Vec::default();
            for i in 0..n {
                den.push(
                    SparsePolynomial::from_coefficients_slice(&[
                        (1, E::Fr::one()),
                        // Weird but `from_repr` and `from` are not suitable for this impl.
                        (0, -E::Fr::from_str(&format!("{}", i)).ok().unwrap()),
                    ])
                    .into(),
                );
            }
            den
        };
        let res: Vec<Polynomial<E::Fr>> = denoninators
            .into_iter()
            .map(|den| numerator.divide_with_q_and_r(&den).unwrap().0)
            .collect();
        res
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
        preprocessed_circuit: &PreProcessedCircuit<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        rng: &mut R,
    ) -> proof::Proof<E>;
}
