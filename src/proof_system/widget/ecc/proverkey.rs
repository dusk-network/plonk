use super::{check_bit_consistency, extract_bit};
use crate::fft::{Evaluations, Polynomial};
use dusk_bls12_381::Scalar;
use dusk_jubjub::EDWARDS_D;

#[derive(Debug, Eq, PartialEq)]
pub struct ProverKey {
    pub q_l: (Polynomial, Evaluations),
    pub q_r: (Polynomial, Evaluations),
    pub q_c: (Polynomial, Evaluations),
    pub q_ecc: (Polynomial, Evaluations),
}

impl ProverKey {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        ecc_separation_challenge: &Scalar,
        w_l_i: &Scalar,      // acc_x or curr_x
        w_l_i_next: &Scalar, //  // next_x
        w_r_i: &Scalar,      // acc_y or curr_y
        w_r_i_next: &Scalar, // next_y
        w_o_i: &Scalar,      // xy_alpha
        w_4_i: &Scalar,      // accumulated_bit
        w_4_i_next: &Scalar, // accumulated_bit_next
    ) -> Scalar {
        let q_ecc_i = &self.q_ecc.1[index];
        let q_c_i = &self.q_c.1[index];

        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let x_beta = &self.q_l.1[index];
        let y_beta = &self.q_r.1[index];

        let acc_x = w_l_i;
        let acc_x_next = w_l_i_next;
        let acc_y = w_r_i;
        let acc_y_next = w_r_i_next;

        let xy_alpha = w_o_i;

        let accumulated_bit = w_4_i;
        let accumulated_bit_next = w_4_i_next;
        let bit = extract_bit(accumulated_bit, accumulated_bit_next);

        // Checks
        //
        // Check bit consistency
        let bit_consistency = check_bit_consistency(bit);

        // Derive y_alpha and x_alpha from bit
        let y_alpha = bit.square() * (y_beta - Scalar::one()) + Scalar::one();
        let x_alpha = bit * x_beta;

        // xy_alpha consistency check
        let xy_consistency = ((bit * q_c_i) - xy_alpha) * kappa;

        // x accumulator consistency check
        let x_3 = acc_x_next;
        let lhs = x_3 + (x_3 * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let rhs = (acc_x * y_alpha) + (acc_y * x_alpha);
        let x_acc_consistency = (lhs - rhs) * kappa_sq;

        // y accumulator consistency check
        let y_3 = acc_y_next;
        let lhs = y_3 - (y_3 * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let rhs = (acc_y * y_alpha) + (acc_x * x_alpha);
        let y_acc_consistency = (lhs - rhs) * kappa_cu;

        let identity = bit_consistency + x_acc_consistency + y_acc_consistency + xy_consistency;

        identity * q_ecc_i * ecc_separation_challenge
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_linearisation(
        &self,
        ecc_separation_challenge: &Scalar,
        a_eval: &Scalar,
        a_next_eval: &Scalar,
        b_eval: &Scalar,
        b_next_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
        q_l_eval: &Scalar,
        q_r_eval: &Scalar,
        q_c_eval: &Scalar,
    ) -> Polynomial {
        let q_ecc_poly = &self.q_ecc.0;

        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let x_beta_eval = q_l_eval;
        let y_beta_eval = q_r_eval;

        let acc_x = a_eval;
        let acc_x_next = a_next_eval;
        let acc_y = b_eval;
        let acc_y_next = b_next_eval;

        let xy_alpha = c_eval;

        let accumulated_bit = d_eval;
        let accumulated_bit_next = d_next_eval;
        let bit = extract_bit(accumulated_bit, accumulated_bit_next);

        // Check bit consistency
        let bit_consistency = check_bit_consistency(bit);

        let y_alpha = bit.square() * (y_beta_eval - Scalar::one()) + Scalar::one();

        let x_alpha = x_beta_eval * bit;

        // xy_alpha consistency check
        let xy_consistency = ((bit * q_c_eval) - xy_alpha) * kappa;

        // x accumulator consistency check
        let x_3 = acc_x_next;
        let lhs = x_3 + (x_3 * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let rhs = (x_alpha * acc_y) + (y_alpha * acc_x);
        let x_acc_consistency = (lhs - rhs) * kappa_sq;

        // y accumulator consistency check
        let y_3 = acc_y_next;
        let lhs = y_3 - (y_3 * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let rhs = (x_alpha * acc_x) + (y_alpha * acc_y);
        let y_acc_consistency = (lhs - rhs) * kappa_cu;

        let a = bit_consistency + x_acc_consistency + y_acc_consistency + xy_consistency;

        q_ecc_poly * &(a * ecc_separation_challenge)
    }
}
