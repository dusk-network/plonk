use crate::commitment_scheme::kzg10::Commitment;
use crate::proof_system::linearisation_poly::ProofEvaluations;
use dusk_bls12_381::{G1Affine, Scalar};

#[derive(Debug)]
pub struct VerifierKey {
    pub q_l: Commitment,
    pub q_r: Commitment,
    pub q_ecc: Commitment,
}

impl VerifierKey {
    pub(crate) fn compute_linearisation_commitment(
        &self,
        ecc_separation_challenge: &Scalar,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let x_beta_poly = evaluations.q_l_eval;
        let y_beta_eval = evaluations.q_r_eval;

        let acc_x = evaluations.a_eval;
        let acc_x_next = evaluations.a_next_eval;
        let acc_y = evaluations.b_eval;
        let acc_y_next = evaluations.b_next_eval;

        let xy_alpha = evaluations.c_eval;

        let accumulated_bit = evaluations.d_eval;
        let accumulated_bit_next = evaluations.d_next_eval;
        let bit = extract_bit(&accumulated_bit, &accumulated_bit_next);

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

        scalars.push(a * ecc_separation_challenge);
        points.push(self.q_ecc.0);
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
