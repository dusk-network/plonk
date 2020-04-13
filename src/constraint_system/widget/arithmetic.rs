use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::{G1Affine, Scalar};

#[derive(Debug)]
pub struct ArithmeticWidget {
    pub q_m: PreProcessedPolynomial,
    pub q_l: PreProcessedPolynomial,
    pub q_r: PreProcessedPolynomial,
    pub q_o: PreProcessedPolynomial,
    pub q_c: PreProcessedPolynomial,
    pub q_4: PreProcessedPolynomial,
    pub q_arith: PreProcessedPolynomial,
}

impl ArithmeticWidget {
    #[allow(clippy::type_complexity)]
    pub fn new(
        selectors: (
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
        ),
    ) -> ArithmeticWidget {
        ArithmeticWidget {
            q_m: PreProcessedPolynomial::new(selectors.0),
            q_l: PreProcessedPolynomial::new(selectors.1),
            q_r: PreProcessedPolynomial::new(selectors.2),
            q_o: PreProcessedPolynomial::new(selectors.3),
            q_c: PreProcessedPolynomial::new(selectors.4),
            q_4: PreProcessedPolynomial::new(selectors.5),
            q_arith: PreProcessedPolynomial::new(selectors.6),
        }
    }
    pub fn compute_quotient_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
    ) -> Scalar {
        let q_m_i = self.q_m.evaluations.as_ref().unwrap()[index];
        let q_l_i = self.q_l.evaluations.as_ref().unwrap()[index];
        let q_r_i = self.q_r.evaluations.as_ref().unwrap()[index];
        let q_o_i = self.q_o.evaluations.as_ref().unwrap()[index];
        let q_c_i = self.q_c.evaluations.as_ref().unwrap()[index];
        let q_4_i = self.q_4.evaluations.as_ref().unwrap()[index];
        let q_arith_i = self.q_arith.evaluations.as_ref().unwrap()[index];

        // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + d(x)q_4(X) + Q_C(X)) * Q_Arith(X)
        //
        let a_1 = w_l_i * w_r_i * q_m_i;
        let a_2 = w_l_i * q_l_i;
        let a_3 = w_r_i * q_r_i;
        let a_4 = w_o_i * q_o_i;
        let a_5 = w_4_i * q_4_i;
        let a_6 = q_c_i;
        (a_1 + a_2 + a_3 + a_4 + a_5 + a_6) * q_arith_i
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        b_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        q_arith_eval: &Scalar,
    ) -> Polynomial {
        let q_m_poly = &self.q_m.polynomial;
        let q_l_poly = &self.q_l.polynomial;
        let q_r_poly = &self.q_r.polynomial;
        let q_o_poly = &self.q_o.polynomial;
        let q_c_poly = &self.q_c.polynomial;
        let q_4_poly = &self.q_4.polynomial;

        // (a_eval * b_eval * q_m_poly + a_eval * q_l + b_eval * q_r + c_eval * q_o + d_eval * q_4 + q_c) * q_arith_eval * alpha
        //
        // a_eval * b_eval * q_m_poly
        let ab = a_eval * b_eval;
        let a_0 = q_m_poly * &ab;

        // a_eval * q_l
        let a_1 = q_l_poly * a_eval;

        // b_eval * q_r
        let a_2 = q_r_poly * b_eval;

        //c_eval * q_o
        let a_3 = q_o_poly * c_eval;

        // d_eval * q_4
        let a_4 = q_4_poly * d_eval;

        let mut a = &a_0 + &a_1;
        a = &a + &a_2;
        a = &a + &a_3;
        a = &a + &a_4;
        a = &a + q_c_poly;
        a = &a * q_arith_eval;

        a
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let q_arith_eval = evaluations.q_arith_eval;
        scalars.push(evaluations.a_eval * evaluations.b_eval * q_arith_eval);
        points.push(self.q_m.commitment.0);

        scalars.push(evaluations.a_eval * q_arith_eval);
        points.push(self.q_l.commitment.0);

        scalars.push(evaluations.b_eval * q_arith_eval);
        points.push(self.q_r.commitment.0);

        scalars.push(evaluations.c_eval * q_arith_eval);
        points.push(self.q_o.commitment.0);

        scalars.push(evaluations.d_eval * q_arith_eval);
        points.push(self.q_4.commitment.0);

        scalars.push(q_arith_eval);
        points.push(self.q_c.commitment.0);
    }
}
