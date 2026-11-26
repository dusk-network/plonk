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

    pub(crate) fn compute_linearization(
        &self,
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
        z_poly: &Polynomial,
    ) -> Polynomial {
        let a = self.compute_linearizer_identity_range_check(
            (a_eval, b_eval, c_eval, d_eval),
            z_challenge,
            (alpha, beta, gamma),
            z_poly,
        );
        let b = self.compute_linearizer_copy_range_check(
            (a_eval, b_eval, c_eval),
            z_eval,
            sigma_1_eval,
            sigma_2_eval,
            sigma_3_eval,
            (alpha, beta, gamma),
            &self.s_sigma_4.0,
        );

        // the poly is increased by 2 after blinding it
        let domain = EvaluationDomain::new(z_poly.degree() - 2).unwrap();
        let c = self.compute_linearizer_check_is_one(
            &domain,
            z_challenge,
            &alpha.square(),
            z_poly,
        );
        &(&a + &b) + &c
    }

    // (a_eval + beta * z_challenge + gamma)(b_eval + beta * K1 * z_challenge +
    // gamma)(c_eval + beta * K2 * z_challenge + gamma) * alpha z(X)
    fn compute_linearizer_identity_range_check(
        &self,
        (a_eval, b_eval, c_eval, d_eval): (
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
        ),
        z_challenge: &BlsScalar,
        (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
        z_poly: &Polynomial,
    ) -> Polynomial {
        let beta_z = beta * z_challenge;

        // a_eval + beta * z_challenge + gamma
        let mut a_0 = a_eval + beta_z;
        a_0 += gamma;

        // b_eval + beta * K1 * z_challenge + gamma
        let beta_z_k1 = K1 * beta_z;
        let mut a_1 = b_eval + beta_z_k1;
        a_1 += gamma;

        // c_eval + beta * K2 * z_challenge + gamma
        let beta_z_k2 = K2 * beta_z;
        let mut a_2 = c_eval + beta_z_k2;
        a_2 += gamma;

        // d_eval + beta * K3 * z_challenge + gamma
        let beta_z_k3 = K3 * beta_z;
        let mut a_3 = d_eval + beta_z_k3;
        a_3 += gamma;

        let mut a = a_0 * a_1;
        a *= a_2;
        a *= a_3;
        a *= alpha; // (a_eval + beta * z_challenge + gamma)(b_eval + beta * K1 *
        // z_challenge + gamma)(c_eval + beta * K2 * z_challenge + gamma)(d_eval
        // + beta * K3 * z_challenge + gamma) * alpha
        z_poly * &a // (a_eval + beta * z_challenge + gamma)(b_eval + beta * K1
        // * z_challenge + gamma)(c_eval + beta * K2 * z_challenge +
        // gamma) * alpha z(X)
    }

    // -(a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma)
    // (c_eval + beta * sigma_3 + gamma) * beta *z_eval * alpha^2 * Sigma_4(X)
    fn compute_linearizer_copy_range_check(
        &self,
        (a_eval, b_eval, c_eval): (&BlsScalar, &BlsScalar, &BlsScalar),
        z_eval: &BlsScalar,
        sigma_1_eval: &BlsScalar,
        sigma_2_eval: &BlsScalar,
        sigma_3_eval: &BlsScalar,
        (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
        s_sigma_4_poly: &Polynomial,
    ) -> Polynomial {
        // a_eval + beta * sigma_1 + gamma
        let beta_sigma_1 = beta * sigma_1_eval;
        let mut a_0 = a_eval + beta_sigma_1;
        a_0 += gamma;

        // b_eval + beta * sigma_2 + gamma
        let beta_sigma_2 = beta * sigma_2_eval;
        let mut a_1 = b_eval + beta_sigma_2;
        a_1 += gamma;

        // c_eval + beta * sigma_3 + gamma
        let beta_sigma_3 = beta * sigma_3_eval;
        let mut a_2 = c_eval + beta_sigma_3;
        a_2 += gamma;

        let beta_z_eval = beta * z_eval;

        let mut a = a_0 * a_1 * a_2;
        a *= beta_z_eval;
        a *= alpha; // (a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 +
        // gamma)(c_eval + beta * sigma_3 + gamma) * beta * z_eval * alpha

        s_sigma_4_poly * &-a // -(a_eval + beta * sigma_1 + gamma)(b_eval +
        // beta * sigma_2 + gamma) (c_eval + beta *
        // sigma_3 + gamma) * beta * z_eval * alpha^2 *
        // Sigma_4(X)
    }

    fn compute_linearizer_check_is_one(
        &self,
        domain: &EvaluationDomain,
        z_challenge: &BlsScalar,
        alpha_sq: &BlsScalar,
        z_coeffs: &Polynomial,
    ) -> Polynomial {
        // Evaluate l_1(z)
        let l_1_z = domain.evaluate_all_lagrange_coefficients(*z_challenge)[0];

        z_coeffs * &(l_1_z * alpha_sq)
    }
}
