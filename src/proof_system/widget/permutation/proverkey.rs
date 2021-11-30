// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::permutation::constants::{K1, K2, K3};
use dusk_bls12_381::BlsScalar;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct ProverKey {
    pub(crate) s_sigma_1: (Polynomial, Evaluations),
    pub(crate) s_sigma_2: (Polynomial, Evaluations),
    pub(crate) s_sigma_3: (Polynomial, Evaluations),
    pub(crate) s_sigma_4: (Polynomial, Evaluations),
    pub(crate) linear_evaluations: Evaluations,
    /* Evaluations of f(x) = X
     * [XXX: Remove this and
     * benchmark if it makes a
     * considerable difference
     * -- These are just the
     * domain elements] */
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        a_w_i: &BlsScalar,
        b_w_i: &BlsScalar,
        c_w_i: &BlsScalar,
        d_w_i: &BlsScalar,
        z_i: &BlsScalar,
        z_i_next: &BlsScalar,
        alpha: &BlsScalar,
        l1_alpha_sq: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> BlsScalar {
        let a = self.compute_quotient_identity_range_check_i(
            index, a_w_i, b_w_i, c_w_i, d_w_i, z_i, alpha, beta, gamma,
        );
        let b = self.compute_quotient_copy_range_check_i(
            index, a_w_i, b_w_i, c_w_i, d_w_i, z_i_next, alpha, beta, gamma,
        );
        let c = self.compute_quotient_term_check_one_i(z_i, l1_alpha_sq);
        a + b + c
    }
    // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta *
    // k2 * X + gamma)(d(X) + beta * k3 * X + gamma)z(X) * alpha
    fn compute_quotient_identity_range_check_i(
        &self,
        index: usize,
        a_w_i: &BlsScalar,
        b_w_i: &BlsScalar,
        c_w_i: &BlsScalar,
        d_w_i: &BlsScalar,
        z_i: &BlsScalar,
        alpha: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> BlsScalar {
        let x = self.linear_evaluations[index];

        (a_w_i + (beta * x) + gamma)
            * (b_w_i + (beta * K1 * x) + gamma)
            * (c_w_i + (beta * K2 * x) + gamma)
            * (d_w_i + (beta * K3 * x) + gamma)
            * z_i
            * alpha
    }
    // (a(x) + beta* Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X)
    // + beta * Sigma3(X) + gamma)(d(X) + beta * Sigma4(X) + gamma) Z(X.omega) *
    // alpha
    fn compute_quotient_copy_range_check_i(
        &self,
        index: usize,
        a_w_i: &BlsScalar,
        b_w_i: &BlsScalar,
        c_w_i: &BlsScalar,
        d_w_i: &BlsScalar,
        z_i_next: &BlsScalar,
        alpha: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> BlsScalar {
        let s_sigma_1_eval = self.s_sigma_1.1[index];
        let s_sigma_2_eval = self.s_sigma_2.1[index];
        let s_sigma_3_eval = self.s_sigma_3.1[index];
        let s_sigma_4_eval = self.s_sigma_4.1[index];

        let product = (a_w_i + (beta * s_sigma_1_eval) + gamma)
            * (b_w_i + (beta * s_sigma_2_eval) + gamma)
            * (c_w_i + (beta * s_sigma_3_eval) + gamma)
            * (d_w_i + (beta * s_sigma_4_eval) + gamma)
            * z_i_next
            * alpha;

        -product
    }
    // L_1(X)[Z(X) - 1]
    fn compute_quotient_term_check_one_i(
        &self,
        z_i: &BlsScalar,
        l1_alpha_sq: &BlsScalar,
    ) -> BlsScalar {
        (z_i - BlsScalar::one()) * l1_alpha_sq
    }

    pub(crate) fn compute_linearisation(
        &self,
        zeta_frak: &BlsScalar,
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
        let a = self.compute_lineariser_identity_range_check(
            (a_eval, b_eval, c_eval, d_eval),
            zeta_frak,
            (alpha, beta, gamma),
            z_poly,
        );
        let b = self.compute_lineariser_copy_range_check(
            (a_eval, b_eval, c_eval),
            z_eval,
            sigma_1_eval,
            sigma_2_eval,
            sigma_3_eval,
            (alpha, beta, gamma),
            &self.s_sigma_4.0,
        );

        let domain = EvaluationDomain::new(z_poly.degree()).unwrap();
        let c = self.compute_lineariser_check_is_one(
            &domain,
            zeta_frak,
            &alpha.square(),
            z_poly,
        );
        &(&a + &b) + &c
    }
    // (a_eval + beta * zeta_frak + gamma)(b_eval + beta * K1 * zeta_frak +
    // gamma)(c_eval + beta * K2 * zeta_frak + gamma) * alpha z(X)
    fn compute_lineariser_identity_range_check(
        &self,
        (a_eval, b_eval, c_eval, d_eval): (
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
        ),
        zeta_frak: &BlsScalar,
        (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
        z_poly: &Polynomial,
    ) -> Polynomial {
        let beta_z = beta * zeta_frak;

        // a_eval + beta * zeta_frak + gamma
        let mut a_0 = a_eval + beta_z;
        a_0 += gamma;

        // b_eval + beta * K1 * zeta_frak + gamma
        let beta_z_k1 = K1 * beta_z;
        let mut a_1 = b_eval + beta_z_k1;
        a_1 += gamma;

        // c_eval + beta * K2 * zeta_frak + gamma
        let beta_z_k2 = K2 * beta_z;
        let mut a_2 = c_eval + beta_z_k2;
        a_2 += gamma;

        // d_eval + beta * K3 * zeta_frak + gamma
        let beta_z_k3 = K3 * beta_z;
        let mut a_3 = d_eval + beta_z_k3;
        a_3 += gamma;

        let mut a = a_0 * a_1;
        a *= a_2;
        a *= a_3;
        a *= alpha; // (a_eval + beta * zeta_frak + gamma)(b_eval + beta * K1 *
                    // zeta_frak + gamma)(c_eval + beta * K2 * zeta_frak + gamma)(d_eval
                    // + beta * K3 * zeta_frak + gamma) * alpha
        z_poly * &a // (a_eval + beta * zeta_frak + gamma)(b_eval + beta * K1
                    // * zeta_frak + gamma)(c_eval + beta * K2 * zeta_frak +
                    // gamma) * alpha z(X)
    }
    // -(a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma)
    // (c_eval + beta * sigma_3 + gamma) * beta *z_eval * alpha^2 * Sigma_4(X)
    fn compute_lineariser_copy_range_check(
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

    fn compute_lineariser_check_is_one(
        &self,
        domain: &EvaluationDomain,
        zeta_frak: &BlsScalar,
        alpha_sq: &BlsScalar,
        z_coeffs: &Polynomial,
    ) -> Polynomial {
        // Evaluate l_1(z)
        let l_1_z = domain.evaluate_all_lagrange_coefficients(*zeta_frak)[0];

        z_coeffs * &(l_1_z * alpha_sq)
    }
}
