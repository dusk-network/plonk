use crate::fft::{Evaluations, Polynomial};
use dusk_bls12_381::Scalar;

#[derive(Debug, Eq, PartialEq)]
pub struct ProverKey {
    pub q_l: (Polynomial, Evaluations),
    pub q_r: (Polynomial, Evaluations),
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

        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

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
        let xy_consistency = (x_alpha * y_alpha) - xy_alpha;

        // x accumulator consistency check
        let x_3 = acc_x_next;
        let lhs = x_3 + (x_3 * xy_alpha * acc_x * acc_y * edwards_d());
        let rhs = (acc_x * y_alpha) + (acc_y * x_alpha);
        let x_acc_consistency = lhs - rhs;

        // y accumulator consistency check
        let y_3 = acc_y_next;
        let lhs = y_3 - (y_3 * xy_alpha * acc_x * acc_y * edwards_d());
        let rhs = (acc_y * y_alpha) + (acc_x * x_alpha);
        let y_acc_consistency = lhs - rhs;

        let identity = bit_consistency * kappa
            + xy_consistency * kappa_sq
            + x_acc_consistency * kappa_cu
            + y_acc_consistency * kappa_qu;

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
    ) -> Polynomial {
        let q_ecc_poly = &self.q_ecc.0;

        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let x_beta_poly = q_l_eval;
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
        let bit_consistency = check_bit_consistency(bit) * kappa;

        let y_alpha = (bit.square() * (y_beta_eval - Scalar::one())) + Scalar::one();

        let x_alpha = x_beta_poly * bit;

        // xy_alpha consistency check
        let xy_consistency = ((x_alpha * y_alpha) - xy_alpha) * kappa_sq;

        // x accumulator consistency check
        let x_3 = acc_x_next;
        let lhs = x_3 + (x_3 * xy_alpha * acc_x * acc_y * edwards_d());
        let rhs = (x_alpha * acc_y) + (y_alpha * acc_x);
        let x_acc_consistency = (lhs - rhs) * kappa_cu;

        // y accumulator consistency check
        let y_3 = acc_y_next;
        let lhs = y_3 - (y_3 * xy_alpha * acc_x * acc_y * edwards_d());
        let rhs = (x_alpha * acc_x) + (y_alpha * acc_y);
        let y_acc_consistency = (lhs - rhs) * kappa_qu;

        let a = xy_consistency + bit_consistency + x_acc_consistency + y_acc_consistency;

        q_ecc_poly * &(a * ecc_separation_challenge)
    }
}

// Bits are accumulated in base2. So we use d(Xw) - 2d(X) to extract the base2 bit
fn extract_bit(curr_acc: &Scalar, next_acc: &Scalar) -> Scalar {
    // Next - 2 * current
    next_acc - (curr_acc + curr_acc)
}

use jubjub::Fq;
fn edwards_d() -> Fq {
    let num = Fq::from(10240);
    let den = Fq::from(10241);
    -(num * den.invert().unwrap())
}

// Ensures that the bit is either +1, -1 or 0
fn check_bit_consistency(bit: Scalar) -> Scalar {
    let one = Scalar::one();
    bit * (bit - one) * (bit + one)
}
