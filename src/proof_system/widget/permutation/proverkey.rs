// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

#![allow(clippy::too_many_arguments)]
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::permutation::constants::{K1, K2, K3};
use dusk_bls12_381::Scalar;

#[derive(Debug, Eq, PartialEq)]
pub struct ProverKey {
    pub left_sigma: (Polynomial, Evaluations),
    pub right_sigma: (Polynomial, Evaluations),
    pub out_sigma: (Polynomial, Evaluations),
    pub fourth_sigma: (Polynomial, Evaluations),
    pub linear_evaluations: Evaluations, // Evaluations of f(x) = X [XXX: Remove this and benchmark if it makes a considerable difference -- These are just the domain elements]
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        z_i: &Scalar,
        z_i_next: &Scalar,
        alpha: &Scalar,
        l1_alpha_sq: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
    ) -> Scalar {
        let a = self.compute_quotient_identity_range_check_i(
            index, w_l_i, w_r_i, w_o_i, w_4_i, z_i, alpha, beta, gamma,
        );
        let b = self.compute_quotient_copy_range_check_i(
            index, w_l_i, w_r_i, w_o_i, w_4_i, z_i_next, alpha, beta, gamma,
        );
        let c = self.compute_quotient_term_check_one_i(z_i, l1_alpha_sq);
        a + b + c
    }
    // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)(d(X) + beta * k3 * X + gamma)z(X) * alpha
    fn compute_quotient_identity_range_check_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        z_i: &Scalar,
        alpha: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
    ) -> Scalar {
        let x = self.linear_evaluations[index];

        (w_l_i + (beta * x) + gamma)
            * (w_r_i + (beta * K1 * x) + gamma)
            * (w_o_i + (beta * K2 * x) + gamma)
            * (w_4_i + (beta * K3 * x) + gamma)
            * z_i
            * alpha
    }
    // (a(x) + beta* Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)(d(X) + beta * Sigma4(X) + gamma) Z(X.omega) * alpha
    fn compute_quotient_copy_range_check_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        z_i_next: &Scalar,
        alpha: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
    ) -> Scalar {
        let left_sigma_eval = self.left_sigma.1[index];
        let right_sigma_eval = self.right_sigma.1[index];
        let out_sigma_eval = self.out_sigma.1[index];
        let fourth_sigma_eval = self.fourth_sigma.1[index];

        let product = (w_l_i + (beta * left_sigma_eval) + gamma)
            * (w_r_i + (beta * right_sigma_eval) + gamma)
            * (w_o_i + (beta * out_sigma_eval) + gamma)
            * (w_4_i + (beta * fourth_sigma_eval) + gamma)
            * z_i_next
            * alpha;

        -product
    }
    // L_1(X)[Z(X) - 1]
    fn compute_quotient_term_check_one_i(&self, z_i: &Scalar, l1_alpha_sq: &Scalar) -> Scalar {
        (z_i - Scalar::one()) * l1_alpha_sq
    }

    pub(crate) fn compute_linearisation(
        &self,
        z_challenge: &Scalar,
        (alpha, beta, gamma): (&Scalar, &Scalar, &Scalar),
        (a_eval, b_eval, c_eval, d_eval): (&Scalar, &Scalar, &Scalar, &Scalar),
        (sigma_1_eval, sigma_2_eval, sigma_3_eval): (&Scalar, &Scalar, &Scalar),
        z_eval: &Scalar,
        z_poly: &Polynomial,
    ) -> Polynomial {
        let a = self.compute_lineariser_identity_range_check(
            (&a_eval, &b_eval, &c_eval, &d_eval),
            z_challenge,
            (alpha, beta, gamma),
            z_poly,
        );
        let b = self.compute_lineariser_copy_range_check(
            (&a_eval, &b_eval, &c_eval),
            z_eval,
            &sigma_1_eval,
            &sigma_2_eval,
            &sigma_3_eval,
            (alpha, beta, gamma),
            &self.fourth_sigma.0,
        );

        let domain = EvaluationDomain::new(z_poly.degree()).unwrap();
        let c = self.compute_lineariser_check_is_one(&domain, z_challenge, &alpha.square(), z_poly);
        &(&a + &b) + &c
    }
    // (a_eval + beta * z_challenge + gamma)(b_eval + beta * K1 * z_challenge + gamma)(c_eval + beta * K2 * z_challenge + gamma) * alpha z(X)
    fn compute_lineariser_identity_range_check(
        &self,
        (a_eval, b_eval, c_eval, d_eval): (&Scalar, &Scalar, &Scalar, &Scalar),
        z_challenge: &Scalar,
        (alpha, beta, gamma): (&Scalar, &Scalar, &Scalar),
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
        a *= alpha; // (a_eval + beta * z_challenge + gamma)(b_eval + beta * K1 * z_challenge + gamma)(c_eval + beta * K2 * z_challenge + gamma)(d_eval + beta * K3 * z_challenge + gamma) * alpha
        z_poly * &a // (a_eval + beta * z_challenge + gamma)(b_eval + beta * K1 * z_challenge + gamma)(c_eval + beta * K2 * z_challenge + gamma) * alpha z(X)
    }
    // -(a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma) (c_eval + beta * sigma_3 + gamma) * beta *z_eval * alpha^2 * Sigma_4(X)
    fn compute_lineariser_copy_range_check(
        &self,
        (a_eval, b_eval, c_eval): (&Scalar, &Scalar, &Scalar),
        z_eval: &Scalar,
        sigma_1_eval: &Scalar,
        sigma_2_eval: &Scalar,
        sigma_3_eval: &Scalar,
        (alpha, beta, gamma): (&Scalar, &Scalar, &Scalar),
        fourth_sigma_poly: &Polynomial,
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
        a *= alpha; // (a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma)(c_eval + beta * sigma_3 + gamma) * beta * z_eval * alpha

        fourth_sigma_poly * &-a // -(a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma) (c_eval + beta * sigma_3 + gamma) * beta * z_eval * alpha^2 * Sigma_4(X)
    }

    fn compute_lineariser_check_is_one(
        &self,
        domain: &EvaluationDomain,
        z_challenge: &Scalar,
        alpha_sq: &Scalar,
        z_coeffs: &Polynomial,
    ) -> Polynomial {
        // Evaluate l_1(z)
        let l_1_z = domain.evaluate_all_lagrange_coefficients(*z_challenge)[0];

        z_coeffs * &(l_1_z * alpha_sq)
    }
}
