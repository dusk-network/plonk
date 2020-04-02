use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::G1Affine;
use bls12_381::Scalar;

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
        w_o_i_next: &Scalar,
        w_4_i: &Scalar,
        w_4_i_next: &Scalar,
        alpha: &Scalar,
    ) -> Scalar {
        let four = Scalar::from(4);

        let q_logic_i = &self.q_logic.evaluations.as_ref().unwrap()[index];
        let q_c_i = &self.q_c.evaluations.as_ref().unwrap()[index];

        let c_0 = (w_l_i_next - w_r_i_next) * w_o_i;
        let c_1 = delta(w_l_i_next - four * w_l_i);
        let c_2 = delta(w_r_i_next - four * w_r_i);
        let c_3 = delta(w_4_i_next - four * w_4_i);
        let c_4 = delta_xor_and(&w_l_i, &w_r_i, &w_o_i_next, &w_4_i, &q_c_i);

        q_logic_i * (c_0 + c_1 + c_2 + c_3 + c_4)
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        a_next_eval: &Scalar,
        b_eval: &Scalar,
        b_next_eval: &Scalar,
        c_eval: &Scalar,
        c_next_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
        q_c_eval: &Scalar,
        q_logic_eval: &Scalar,
        alpha: &Scalar,
    ) -> Polynomial {
        let four = Scalar::from(4);

        let q_logic_poly = &self.q_logic.polynomial;

        let c_0 = (a_next_eval - b_next_eval) * c_eval;
        let c_1 = delta(a_next_eval - four * a_eval);
        let c_2 = delta(b_next_eval - four * b_eval);
        let c_3 = delta(d_next_eval - four * d_eval);
        let c_4 = delta_xor_and(&a_eval, &b_eval, &c_next_eval, &d_eval, q_c_eval);
        q_logic_poly * &(c_0 + c_1 + c_2 + c_3 + c_4)
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
        alpha: &Scalar,
    ) {
        let four = Scalar::from(4);

        let c_0 = (evaluations.a_next_eval - evaluations.b_next_eval) * evaluations.c_eval;
        let c_1 = delta(evaluations.a_next_eval - four * evaluations.a_eval);
        let c_2 = delta(evaluations.b_next_eval - four * evaluations.b_eval);
        let c_3 = delta(evaluations.d_next_eval - four * evaluations.d_eval);
        let c_4 = delta_xor_and(
            &evaluations.a_eval,
            &evaluations.b_eval,
            &evaluations.c_next_eval,
            &evaluations.d_eval,
            &evaluations.q_c_eval,
        );
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

/// TRY THE EQ with W_O_NEXT
//  s * (s * (9 * c - 3 * (a + b)) + 3 * (c + a + b) + w * (w * (4 * w - 18 * (a + b) + 81) + 18 * (a^2  + b^2 ) - 81 * (a +b) + 83))
fn delta_xor_and(
    w_l: &Scalar,
    w_r: &Scalar,
    w_o_next: &Scalar,
    w_4: &Scalar,
    s: &Scalar,
) -> Scalar {
    let nine = Scalar::from(9u64);
    let three = Scalar::from(3u64);
    let four = Scalar::from(4u64);
    let eighteen = Scalar::from(18u64);
    let eighty_one = Scalar::from(81u64);
    let eighty_three = Scalar::from(83u64);
    s * (s * (nine * w_4 - (three * (w_l + w_r)))
        + three * (w_l + w_r + w_4)
        + w_o_next
            * (w_o_next * (four * w_o_next - eighteen * (w_l + w_r) + eighty_one)
                + eighteen * (w_l.square() + w_r.square())
                - eighty_one * (w_l + w_r)
                + eighty_three))
}
/*
sage: a = b = 2
sage: c = 4
sage: d = 0
sage: s * (s * (9 * c - 3 * (a + b)) + 3 * (c + a + b) + w * (w * (4 * w - 18 * (a + b) + 81) + 18 * (a^2  + b^2 ) - 81 * (a +b) + 83))
0
sage:
*/
