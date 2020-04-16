// Functions with a large number of args are permitted to achieve a
// maximum performance and minimum circuit sizes, as well as composition times.
#![allow(clippy::too_many_arguments)]
use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::permutation::constants::{K1, K2, K3};
use crate::proving_system::linearisation_poly::ProofEvaluations;
use bls12_381::{G1Affine, Scalar};
use rayon::prelude::*;

#[derive(Debug)]
pub struct PermutationWidget {
    pub left_sigma: PreProcessedPolynomial,
    pub right_sigma: PreProcessedPolynomial,
    pub out_sigma: PreProcessedPolynomial,
    pub fourth_sigma: PreProcessedPolynomial,
    pub linear_evaluations: Evaluations, // Evaluations of f(x) = X
}

impl PermutationWidget {
    pub fn new(
        left_sigma: (Polynomial, Commitment, Option<Evaluations>),
        right_sigma: (Polynomial, Commitment, Option<Evaluations>),
        out_sigma: (Polynomial, Commitment, Option<Evaluations>),
        fourth_sigma: (Polynomial, Commitment, Option<Evaluations>),
        linear_evaluations: Evaluations,
    ) -> PermutationWidget {
        PermutationWidget {
            left_sigma: PreProcessedPolynomial::new(left_sigma),
            right_sigma: PreProcessedPolynomial::new(right_sigma),
            out_sigma: PreProcessedPolynomial::new(out_sigma),
            fourth_sigma: PreProcessedPolynomial::new(fourth_sigma),
            linear_evaluations,
        }
    }

    pub fn compute_quotient_i(
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
        let left_sigma_eval = self.left_sigma.evaluations.as_ref().unwrap()[index];
        let right_sigma_eval = self.right_sigma.evaluations.as_ref().unwrap()[index];
        let out_sigma_eval = self.out_sigma.evaluations.as_ref().unwrap()[index];
        let fourth_sigma_eval = self.fourth_sigma.evaluations.as_ref().unwrap()[index];

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

    pub fn compute_linearisation(
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
            &self.fourth_sigma.polynomial,
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

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
        z_challenge: &Scalar,
        (alpha, beta, gamma): (&Scalar, &Scalar, &Scalar),
        l1_eval: &Scalar,
        z_comm: G1Affine,
    ) {
        let alpha_sq = alpha * alpha;

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
        points.push(self.fourth_sigma.commitment.0);
    }
}

#[allow(dead_code)]
fn compute_first_lagrange_poly_scaled(domain: &EvaluationDomain, scale: Scalar) -> Polynomial {
    let mut x_evals = vec![Scalar::zero(); domain.size()];
    x_evals[0] = scale;
    domain.ifft_in_place(&mut x_evals);
    Polynomial::from_coefficients_vec(x_evals)
}
#[allow(dead_code)]
/// Ensures that the polynomial evaluated at the first root of unity is one
pub fn compute_is_one_polynomial(
    domain: &EvaluationDomain,
    z_eval_4n: &[Scalar],
    alpha_sq: Scalar,
) -> Evaluations {
    let n = domain.size();
    let domain_4n = EvaluationDomain::new(4 * n).unwrap();

    let l1_poly_alpha = compute_first_lagrange_poly_scaled(domain, alpha_sq);

    let alpha_sq_l1_evals = domain_4n.coset_fft(&l1_poly_alpha.coeffs);

    let t_4: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| alpha_sq_l1_evals[i] * (z_eval_4n[i] - Scalar::one()))
        .collect();
    Evaluations::from_vec_and_domain(t_4, domain_4n)
}
