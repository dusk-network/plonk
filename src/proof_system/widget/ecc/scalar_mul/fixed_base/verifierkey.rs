// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

use super::{check_bit_consistency, extract_bit};
use crate::commitment_scheme::kzg10::Commitment;
use crate::proof_system::linearisation_poly::ProofEvaluations;
use dusk_bls12_381::{G1Affine, Scalar};
use dusk_jubjub::EDWARDS_D;

#[derive(Debug, PartialEq, Eq)]
pub struct VerifierKey {
    pub q_l: Commitment,
    pub q_r: Commitment,
    pub q_fixed_group_add: Commitment,
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
        let bit_consistency = check_bit_consistency(bit);

        let y_alpha = (bit.square() * (y_beta_eval - Scalar::one())) + Scalar::one();

        let x_alpha = x_beta_poly * bit;

        // xy_alpha consistency check
        let xy_consistency = ((bit * evaluations.q_c_eval) - xy_alpha) * kappa;

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

        scalars.push(a * ecc_separation_challenge);
        points.push(self.q_fixed_group_add.0);
    }
}
