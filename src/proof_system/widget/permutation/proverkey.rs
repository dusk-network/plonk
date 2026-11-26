// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
use dusk_bls12_381::BlsScalar;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Serialize,
    ser::{ScratchSpace, Serializer},
};

use crate::composer::permutation::constants::{K1, K2, K3};
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};

#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct ProverKey {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_1: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_2: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_3: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_4: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) linear_evaluations: Evaluations,
}

#[derive(Clone, Copy)]
pub(crate) struct PermutationChallenges {
    alpha: BlsScalar,
    beta: BlsScalar,
    beta_k1: BlsScalar,
    beta_k2: BlsScalar,
    beta_k3: BlsScalar,
    gamma: BlsScalar,
}

impl PermutationChallenges {
    pub(crate) fn new(
        alpha: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> Self {
        Self {
            alpha: *alpha,
            beta: *beta,
            beta_k1: beta * K1,
            beta_k2: beta * K2,
            beta_k3: beta * K3,
            gamma: *gamma,
        }
    }
}

impl ProverKey {
    #[inline]
    pub(crate) fn compute_quotient_i_with_challenges(
        &self,
        index: usize,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        z_i: &BlsScalar,
        z_i_w: &BlsScalar,
        l1_alpha_sq: &BlsScalar,
        challenges: &PermutationChallenges,
    ) -> BlsScalar {
        let x = self.linear_evaluations[index];
        let a_g = a_i + challenges.gamma;
        let b_g = b_i + challenges.gamma;
        let c_g = c_i + challenges.gamma;
        let d_g = d_i + challenges.gamma;

        let identity = (a_g + challenges.beta * x)
            * (b_g + challenges.beta_k1 * x)
            * (c_g + challenges.beta_k2 * x)
            * (d_g + challenges.beta_k3 * x)
            * z_i;

        let s_sigma_1_eval = self.s_sigma_1.1[index];
        let s_sigma_2_eval = self.s_sigma_2.1[index];
        let s_sigma_3_eval = self.s_sigma_3.1[index];
        let s_sigma_4_eval = self.s_sigma_4.1[index];

        let copy = (a_g + challenges.beta * s_sigma_1_eval)
            * (b_g + challenges.beta * s_sigma_2_eval)
            * (c_g + challenges.beta * s_sigma_3_eval)
            * (d_g + challenges.beta * s_sigma_4_eval)
            * z_i_w;

        let check_one = (z_i - BlsScalar::one()) * l1_alpha_sq;
        (identity - copy) * challenges.alpha + check_one
    }

    /// Returns `(z_poly_scalar, s_sigma_4_scalar)` for the permutation
    /// contribution to the linearization polynomial.
    pub(crate) fn linearization_scalars(
        domain: &EvaluationDomain,
        z_challenge: &BlsScalar,
        (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
        (a_eval, b_eval, c_eval, d_eval): (
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
        ),
        (sigma_1_eval, sigma_2_eval, sigma_3_eval): (
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
        ),
        z_eval: &BlsScalar,
    ) -> (BlsScalar, BlsScalar) {
        let beta_z = beta * z_challenge;
        let id_scalar = (a_eval + beta_z + gamma)
            * (b_eval + K1 * beta_z + gamma)
            * (c_eval + K2 * beta_z + gamma)
            * (d_eval + K3 * beta_z + gamma)
            * alpha;

        let l_1_z = domain.evaluate_first_lagrange_coefficient(*z_challenge);
        let z_poly_scalar = id_scalar + l_1_z * alpha.square();

        let copy_scalar = -((a_eval + beta * sigma_1_eval + gamma)
            * (b_eval + beta * sigma_2_eval + gamma)
            * (c_eval + beta * sigma_3_eval + gamma)
            * (beta * z_eval)
            * alpha);

        (z_poly_scalar, copy_scalar)
    }
}
