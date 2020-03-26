use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::{G1Affine, Scalar};

pub struct ArithmeticWidget {
    pub qM: PreProcessedPolynomial,
    pub qL: PreProcessedPolynomial,
    pub qR: PreProcessedPolynomial,
    pub qO: PreProcessedPolynomial,
    pub qC: PreProcessedPolynomial,
    pub q4: PreProcessedPolynomial,
    pub qArith: PreProcessedPolynomial,
}

impl ArithmeticWidget {
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
            qM: PreProcessedPolynomial::new(selectors.0),
            qL: PreProcessedPolynomial::new(selectors.1),
            qR: PreProcessedPolynomial::new(selectors.2),
            qO: PreProcessedPolynomial::new(selectors.3),
            qC: PreProcessedPolynomial::new(selectors.4),
            q4: PreProcessedPolynomial::new(selectors.5),
            qArith: PreProcessedPolynomial::new(selectors.6),
        }
    }
    pub fn compute_quotient(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        pi_i: &Scalar,
    ) -> Scalar {
        let q_m_i = self.qM.evaluations.as_ref().unwrap()[index];
        let q_l_i = self.qL.evaluations.as_ref().unwrap()[index];
        let q_r_i = self.qR.evaluations.as_ref().unwrap()[index];
        let q_o_i = self.qO.evaluations.as_ref().unwrap()[index];
        let q_c_i = self.qC.evaluations.as_ref().unwrap()[index];
        let q_4_i = self.q4.evaluations.as_ref().unwrap()[index];
        let q_arith_i = self.qArith.evaluations.as_ref().unwrap()[index];

        // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + d(x)q_4(X) + PI(X) + Q_C(X)) * Q_Arith(X)
        //
        let a_1 = w_l_i * w_r_i * q_m_i;
        let a_2 = w_l_i * q_l_i;
        let a_3 = w_r_i * q_r_i;
        let a_4 = w_o_i * q_o_i;
        let a_5 = w_4_i * q_4_i;
        let a_6 = q_c_i + pi_i;
        let a = (a_1 + a_2 + a_3 + a_4 + a_5 + a_6) * q_arith_i;

        a
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        b_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        q_arith_eval: &Scalar,
    ) -> Polynomial {
        let q_m_poly = &self.qM.polynomial;
        let q_l_poly = &self.qL.polynomial;
        let q_r_poly = &self.qR.polynomial;
        let q_o_poly = &self.qO.polynomial;
        let q_c_poly = &self.qC.polynomial;
        let q_4_poly = &self.q4.polynomial;

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
        points.push(self.qM.commitment.0);

        scalars.push(evaluations.a_eval * q_arith_eval);
        points.push(self.qL.commitment.0);

        scalars.push(evaluations.b_eval * q_arith_eval);
        points.push(self.qR.commitment.0);

        scalars.push(evaluations.c_eval * q_arith_eval);
        points.push(self.qO.commitment.0);

        scalars.push(evaluations.d_eval * q_arith_eval);
        points.push(self.q4.commitment.0);

        scalars.push(q_arith_eval);
        points.push(self.qC.commitment.0);
    }
}
