use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::Polynomial;
use bls12_381::G1Affine;
use bls12_381::Scalar;

pub struct PermutationWidget {
    pub left_sigma: PreProcessedPolynomial,
    pub right_sigma: PreProcessedPolynomial,
    pub out_sigma: PreProcessedPolynomial,
    pub fourth_sigma: PreProcessedPolynomial,
}

impl PermutationWidget {
    pub fn new(
        left_sigma: (Polynomial, Commitment),
        right_sigma: (Polynomial, Commitment),
        out_sigma: (Polynomial, Commitment),
        fourth_sigma: (Polynomial, Commitment),
    ) -> PermutationWidget {
        PermutationWidget {
            left_sigma: PreProcessedPolynomial::new((left_sigma.0, left_sigma.1, None)),
            right_sigma: PreProcessedPolynomial::new((right_sigma.0, right_sigma.1, None)),
            out_sigma: PreProcessedPolynomial::new((out_sigma.0, out_sigma.1, None)),
            fourth_sigma: PreProcessedPolynomial::new((fourth_sigma.0, fourth_sigma.1, None)),
        }
    }

    pub fn compute_quotient(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        w_4_i_next: &Scalar,
    ) -> Scalar {
        todo!()
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        b_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
    ) -> Polynomial {
        todo!()
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        todo!()
    }
}
