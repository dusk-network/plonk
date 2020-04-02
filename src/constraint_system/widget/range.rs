use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::G1Affine;
use bls12_381::Scalar;

pub struct RangeWidget {
    pub q_range: PreProcessedPolynomial,
}

impl RangeWidget {
    pub fn new(selector: (Polynomial, Commitment, Option<Evaluations>)) -> RangeWidget {
        RangeWidget {
            q_range: PreProcessedPolynomial::new(selector),
        }
    }

    pub fn compute_quotient_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        w_4_i_next: &Scalar,
    ) -> Scalar {
        let four = Scalar::from(4);

        let q_range_i = &self.q_range.evaluations.as_ref().unwrap()[index];

        // Delta([c(X) - 4 * d(X)]) + Delta([b(X) - 4 * c(X)]) + Delta([a(X) - 4 * b(X)]) + Delta([d(Xg) - 4 * a(X)]) * Q_Range(X)
        //
        let b_1 = delta(w_o_i - four * w_4_i);
        let b_2 = delta(w_r_i - four * w_o_i);
        let b_3 = delta(w_l_i - four * w_r_i);
        let b_4 = delta(w_4_i_next - four * w_l_i);
        (b_1 + b_2 + b_3 + b_4) * q_range_i
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        b_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
    ) -> Polynomial {
        let four = Scalar::from(4);

        let q_range_poly = &self.q_range.polynomial;

        // Delta([c_eval - 4 * d_eval]) + Delta([b_eval - 4 * c_eval]) + Delta([a_eval - 4 * b_eval]) + Delta([d_next_eval - 4 * a_eval]) * Q_Range(X)
        let b_1 = delta(c_eval - four * d_eval);
        let b_2 = delta(b_eval - four * c_eval);
        let b_3 = delta(a_eval - four * b_eval);
        let b_4 = delta(d_next_eval - four * a_eval);
        q_range_poly * &(b_1 + b_2 + b_3 + b_4)
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let four = Scalar::from(4);

        let b_1 = delta(evaluations.c_eval - (four * evaluations.d_eval));
        let b_2 = delta(evaluations.b_eval - four * evaluations.c_eval);
        let b_3 = delta(evaluations.a_eval - four * evaluations.b_eval);
        let b_4 = delta(evaluations.d_next_eval - (four * evaluations.a_eval));

        scalars.push(b_1 + b_2 + b_3 + b_4);
        points.push(self.q_range.commitment.0);
    }
}

// Computes f(f-1)(f-2)(f-3)
fn delta(f: Scalar) -> Scalar {
    let f_1 = f - Scalar::one();
    let f_2 = f - Scalar::from(2);
    let f_3 = f - Scalar::from(3);
    f * f_1 * f_2 * f_3
}
