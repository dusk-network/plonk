// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::too_many_arguments)]

use crate::commitment_scheme::kzg10::Commitment;
use crate::permutation::constants::{K1, K2, K3};
use crate::proof_system::linearisation_poly::ProofEvaluations;
use dusk_bls12_381::{BlsScalar, G1Affine};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct VerifierKey {
    pub left_sigma: Commitment,
    pub right_sigma: Commitment,
    pub out_sigma: Commitment,
    pub fourth_sigma: Commitment,
}

impl VerifierKey {
    pub(crate) fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<BlsScalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
        z_challenge: &BlsScalar,
        (alpha, beta, gamma, delta, epsilon): (
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
        ),
        l1_eval: &BlsScalar,
        ln_eval: &BlsScalar,
        t_eval: &BlsScalar,
        t_next_eval: &BlsScalar,
        z_comm: G1Affine,
        h_1_comm: G1Affine,
        h_2_comm: G1Affine,
        p_comm: G1Affine,
    ) {
        // Compute powers of alpha
        let alpha_sq = alpha.square();
        let alpha_4 = alpha_sq * alpha_sq;
        let alpha_5 = alpha_4 * alpha;
        let alpha_6 = alpha_5 * alpha;
        let alpha_7 = alpha_6 * alpha;

        // (a_eval + beta * z + gamma)(b_eval + beta * z * k1 + gamma)(c_eval + beta * k2 * z + gamma)(d_eval + beta * k3 * z + gamma) * alpha
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

        // -(a_eval + beta * sigma_1_eval + gamma)(b_eval + beta * sigma_2_eval + gamma)(c_eval + beta * sigma_3_eval + gamma) * alpha^2
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

        // l_n(z) * alpha^6
        let a = { ln_eval * alpha };
        scalars.push(a);
        points.push(h_1_comm);

        // -(z - 1) * p_eval * (epsilon( 1+ delta) + h_1_eval +(delta * h_1_next_eval) * alpha^5
        let b = {
            let q_0 = z_challenge - BlsScalar::one();

            let q_1 = epsilon * (BlsScalar::one() + delta)
                + evaluations.h_1_eval
                + (delta * evaluations.h_1_next_eval);

            -(q_0 * evaluations.lookup_perm_eval * q_1 * alpha_5)
        };
        scalars.push(b);
        points.push(h_2_comm);

        // (z - 1)(1 + delta)(e + f_eval)(epsilon(1 + delta) + t_eval + (delta * t_next_eval) * alpha^5 + l_1(z) * alpha^4 + l_n(z) * alpha^7)
        let c = {
            let q_0 = z_challenge - BlsScalar::one();

            let q_1 = BlsScalar::one() + delta;

            let q_2 = epsilon + evaluations.f_eval;

            let q_3 = (epsilon * q_1 + t_eval + (delta * t_next_eval)) * alpha_5;

            let q_4 = l1_eval * alpha_4;

            let q_5 = ln_eval * alpha_7;

            (q_1 * q_2 * q_3) + q_4 + q_5
        };
        scalars.push(c);
        points.push(p_comm);
    }
}
