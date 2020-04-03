#![allow(clippy::too_many_arguments)]
use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::G1Affine;
use bls12_381::Scalar;

#[derive(Debug)]
pub struct LogicWidget {
    pub q_c: PreProcessedPolynomial,
    pub q_logic: PreProcessedPolynomial,
}

impl LogicWidget {
    pub fn new(
        q_c: (Polynomial, Commitment, Option<Evaluations>),
        q_logic: (Polynomial, Commitment, Option<Evaluations>),
    ) -> LogicWidget {
        LogicWidget {
            q_logic: PreProcessedPolynomial::new(q_logic),
            q_c: PreProcessedPolynomial::new(q_c),
        }
    }

    pub fn compute_quotient_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_l_i_next: &Scalar,
        w_r_i: &Scalar,
        w_r_i_next: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        w_4_i_next: &Scalar,
    ) -> Scalar {
        let four = Scalar::from(4);

        let q_logic_i = &self.q_logic.evaluations.as_ref().unwrap()[index];
        let q_c_i = &self.q_c.evaluations.as_ref().unwrap()[index];

        let a = w_l_i_next - four * w_l_i;
        let c_0 = delta(a);

        let b = w_r_i_next - four * w_r_i;
        let c_1 = delta(b);

        let d = w_4_i_next - four * w_4_i;
        let c_2 = delta(d);

        let w = w_o_i;

        let c_3 = w - a * b;

        let c_4 = delta_xor_and(&a, &b, w, &d, &q_c_i);

        q_logic_i * (c_3 + c_0 + c_1 + c_2 + c_4)
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        a_next_eval: &Scalar,
        b_eval: &Scalar,
        b_next_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
        q_c_eval: &Scalar,
    ) -> Polynomial {
        let four = Scalar::from(4);

        let q_logic_poly = &self.q_logic.polynomial;

        let a = a_next_eval - four * a_eval;
        let c_0 = delta(a);

        let b = b_next_eval - four * b_eval;
        let c_1 = delta(b);

        let d = d_next_eval - four * d_eval;
        let c_2 = delta(d);

        let w = c_eval;

        let c_3 = w - a * b;

        let c_4 = delta_xor_and(&a, &b, w, &d, &q_c_eval);

        q_logic_poly * &(c_0 + c_1 + c_2 + c_3 + c_4)
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let four = Scalar::from(4);

        let a = evaluations.a_next_eval - four * evaluations.a_eval;
        let c_0 = delta(a);

        let b = evaluations.b_next_eval - four * evaluations.b_eval;
        let c_1 = delta(b);

        let d = evaluations.d_next_eval - four * evaluations.d_eval;
        let c_2 = delta(d);

        let w = evaluations.c_eval;

        let c_3 = w - a * b;

        let c_4 = delta_xor_and(&a, &b, &w, &d, &evaluations.q_c_eval);
        scalars.push(c_0 + c_1 + c_2 + c_3 + c_4);
        points.push(self.q_logic.commitment.0);
    }
}

// Computes f(f-1)(f-2)(f-3)
fn delta(f: Scalar) -> Scalar {
    let f_1 = f - Scalar::one();
    let f_2 = f - Scalar::from(2);
    let f_3 = f - Scalar::from(3);
    f * f_1 * f_2 * f_3
}

#[allow(non_snake_case)]
// The identity we want to check is q_logic * A = 0
// A = B + E
// B = q_c * [9c - 3(a+b)]
// E = 3(a+b+c) - 2F
// F = w[w(4w - 18(a+b) + 81) + 18(a^2 + b^2) - 81(a+b) + 83]
fn delta_xor_and(a: &Scalar, b: &Scalar, w: &Scalar, c: &Scalar, q_c: &Scalar) -> Scalar {
    let nine = Scalar::from(9u64);
    let two = Scalar::from(2u64);
    let three = Scalar::from(3u64);
    let four = Scalar::from(4u64);
    let eighteen = Scalar::from(18u64);
    let eighty_one = Scalar::from(81u64);
    let eighty_three = Scalar::from(83u64);

    let F = w
        * (w * (four * w - eighteen * (a + b) + eighty_one) + eighteen * (a.square() + b.square())
            - eighty_one * (a + b)
            + eighty_three);
    let E = three * (a + b + c) - (two * F);
    let B = q_c * ((nine * c) - three * (a + b));
    B + E
}
