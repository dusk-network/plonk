// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::kzg10::Commitment;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) struct VerifierKey {
    pub(crate) q_l: Commitment,
    pub(crate) q_r: Commitment,
    pub(crate) q_fixed_group_add: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearisation_poly::ProofEvaluations;
    use crate::proof_system::widget::ecc::scalar_mul::fixed_base::proverkey::{
        check_bit_consistency, extract_bit,
    };
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{BlsScalar, G1Affine};
    use dusk_jubjub::EDWARDS_D;

    impl VerifierKey {
        pub(crate) fn compute_linearisation_commitment(
            &self,
            ecc_separation_challenge: &BlsScalar,
            scalars: &mut Vec<BlsScalar>,
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

            let y_alpha = (bit.square() * (y_beta_eval - BlsScalar::one()))
                + BlsScalar::one();

            let x_alpha = x_beta_poly * bit;

            // xy_alpha consistency check
            let xy_consistency =
                ((bit * evaluations.q_c_eval) - xy_alpha) * kappa;

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

            let a = bit_consistency
                + x_acc_consistency
                + y_acc_consistency
                + xy_consistency;

            scalars.push(a * ecc_separation_challenge);
            points.push(self.q_fixed_group_add.0);
        }
    }
}
