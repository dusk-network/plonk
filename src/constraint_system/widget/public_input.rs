use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::G1Affine;
use bls12_381::Scalar;

pub struct PublicInputWidget {}

impl PublicInputWidget {
    pub fn compute_quotient(&self, index: usize, pi_i: &Scalar) -> Scalar {
        pi_i
    }

    pub fn compute_linearisation(&self) -> Polynomial {
        Polynomial::zero()
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
    }
}
