#![allow(clippy::too_many_arguments)]
use super::{delta, delta_xor_and};
use crate::fft::{Evaluations, Polynomial};

use dusk_bls12_381::Scalar;

#[derive(Debug, Eq, PartialEq)]
pub struct ProverKey {
    pub q_c: (Polynomial, Evaluations),
    pub q_logic: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        logic_separation_challenge: &Scalar,
        w_l_i: &Scalar,
        w_l_i_next: &Scalar,
        w_r_i: &Scalar,
        w_r_i_next: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        w_4_i_next: &Scalar,
    ) -> Scalar {
        let four = Scalar::from(4);

        let q_logic_i = &self.q_logic.1[index];
        let q_c_i = &self.q_c.1[index];

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = w_l_i_next - four * w_l_i;
        let c_0 = delta(a);

        let b = w_r_i_next - four * w_r_i;
        let c_1 = delta(b) * kappa;

        let d = w_4_i_next - four * w_4_i;
        let c_2 = delta(d) * kappa_sq;

        let w = w_o_i;
        let c_3 = (w - a * b) * kappa_cu;

        let c_4 = delta_xor_and(&a, &b, w, &d, &q_c_i) * kappa_qu;

        q_logic_i * (c_3 + c_0 + c_1 + c_2 + c_4) * logic_separation_challenge
    }

    pub(crate) fn compute_linearisation(
        &self,
        logic_separation_challenge: &Scalar,
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
        let q_logic_poly = &self.q_logic.0;

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = a_next_eval - four * a_eval;
        let c_0 = delta(a);

        let b = b_next_eval - four * b_eval;
        let c_1 = delta(b) * kappa;

        let d = d_next_eval - four * d_eval;
        let c_2 = delta(d) * kappa_sq;

        let w = c_eval;
        let c_3 = (w - a * b) * kappa_cu;

        let c_4 = delta_xor_and(&a, &b, w, &d, &q_c_eval) * kappa_qu;

        let t = (c_0 + c_1 + c_2 + c_3 + c_4) * logic_separation_challenge;

        q_logic_poly * &t
    }
}
