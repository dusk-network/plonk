// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::kzg10::Commitment;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) struct VerifierKey {
    pub(crate) left_sigma: Commitment,
    pub(crate) right_sigma: Commitment,
    pub(crate) out_sigma: Commitment,
    pub(crate) fourth_sigma: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::permutation::constants::{K1, K2, K3};
    use crate::proof_system::linearisation_poly::ProofEvaluations;
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{BlsScalar, G1Affine};

    impl VerifierKey {
        pub(crate) fn compute_linearisation_commitment(
            &self,
            scalars: &mut Vec<BlsScalar>,
            points: &mut Vec<G1Affine>,
            evaluations: &ProofEvaluations,
            z_challenge: &BlsScalar,
            (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
            l1_eval: &BlsScalar,
            z_comm: G1Affine,
        ) {
            let alpha_sq = alpha.square();

            // (a_eval + beta * z + gamma)(b_eval + beta * z * k1 +
            // gamma)(c_eval + beta * k2 * z + gamma)(d_eval + beta
            // * k3 * z + gamma) * alpha
            let x = {
                let beta_z = beta * z_challenge;
                let q_0 = evaluations.a_eval + beta_z + gamma;

                let beta_k1_z = beta * K1 * z_challenge;
                let q_1 = evaluations.b_eval + beta_k1_z + gamma;

                let beta_k2_z = beta * K2 * z_challenge;
                let q_2 = evaluations.c_eval + beta_k2_z + gamma;

                let beta_k3_z = beta * K3 * z_challenge;
                let q_3 = (evaluations.d_eval + beta_k3_z + gamma) * alpha;

                q_0 * q_1 * q_2 * q_3
            };

            // l1(z) * alpha^2
            let r = l1_eval * alpha_sq;

            scalars.push(x + r);
            points.push(z_comm);

            // -(a_eval + beta * sigma_1_eval + gamma)(b_eval + beta *
            // sigma_2_eval + gamma)(c_eval + beta * sigma_3_eval +
            // gamma) * alpha^2
            let y = {
                let beta_sigma_1 = beta * evaluations.left_sigma_eval;
                let q_0 = evaluations.a_eval + beta_sigma_1 + gamma;

                let beta_sigma_2 = beta * evaluations.right_sigma_eval;
                let q_1 = evaluations.b_eval + beta_sigma_2 + gamma;

                let beta_sigma_3 = beta * evaluations.out_sigma_eval;
                let q_2 = evaluations.c_eval + beta_sigma_3 + gamma;

                let q_3 = beta * evaluations.perm_eval * alpha;

                -(q_0 * q_1 * q_2 * q_3)
            };
            scalars.push(y);
            points.push(self.fourth_sigma.0);
        }
    }
}
