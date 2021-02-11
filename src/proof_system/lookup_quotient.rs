// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::widget::PlookupProverKey;
use anyhow::{Error, Result};
use dusk_bls12_381::BlsScalar;
use rayon::prelude::*;

/// This quotient polynomial can only be used for the standard composer
/// Each composer will need to implement their own method for computing the quotient polynomial

/// Computes the quotient polynomial
pub(crate) fn compute(
    domain: &EvaluationDomain,
    prover_key: &PlookupProverKey,
    z_poly: &Polynomial,
    p_poly: &Polynomial,
    (w_l_poly, w_r_poly, w_o_poly, w_4_poly): (&Polynomial, &Polynomial, &Polynomial, &Polynomial),
    f_poly: &Polynomial,
    t_poly: &Polynomial,
    h_1_poly: &Polynomial,
    h_2_poly: &Polynomial,
    public_inputs_poly: &Polynomial,
    (
        alpha,
        beta,
        gamma,
        delta,
        epsilon,
        zeta,
        range_challenge,
        logic_challenge,
        fixed_base_challenge,
        var_base_challenge,
        lookup_challenge,
    ): &(
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
    ),
) -> Result<Polynomial, Error> {
    // Compute 4n eval of z(X)
    let domain_4n = EvaluationDomain::new(4 * domain.size())?;
    let mut z_eval_4n = domain_4n.coset_fft(&z_poly);
    z_eval_4n.push(z_eval_4n[0]);
    z_eval_4n.push(z_eval_4n[1]);
    z_eval_4n.push(z_eval_4n[2]);
    z_eval_4n.push(z_eval_4n[3]);

    // Compute 4n eval of p(X)
    let mut p_eval_4n = domain_4n.coset_fft(&p_poly);
    p_eval_4n.push(p_eval_4n[0]);
    p_eval_4n.push(p_eval_4n[1]);
    p_eval_4n.push(p_eval_4n[2]);
    p_eval_4n.push(p_eval_4n[3]);

    // Compute 4n evals of table poly, t(x)
    let mut t_eval_4n = domain_4n.coset_fft(&t_poly);
    t_eval_4n.push(t_eval_4n[0]);
    t_eval_4n.push(t_eval_4n[1]);
    t_eval_4n.push(t_eval_4n[2]);
    t_eval_4n.push(t_eval_4n[3]);

    // Compute f(x)
    let f_eval = domain_4n.fft(&f_poly);

    // Compute 4n eval of h_1
    let mut h_1_eval_4n = domain_4n.coset_fft(&h_1_poly);
    h_1_eval_4n.push(h_1_eval_4n[0]);
    h_1_eval_4n.push(h_1_eval_4n[1]);
    h_1_eval_4n.push(h_1_eval_4n[2]);
    h_1_eval_4n.push(h_1_eval_4n[3]);

    // Compute 4n eval of h_2
    let mut h_2_eval_4n = domain_4n.coset_fft(&h_2_poly);
    h_2_eval_4n.push(h_2_eval_4n[0]);
    h_2_eval_4n.push(h_2_eval_4n[1]);
    h_2_eval_4n.push(h_2_eval_4n[2]);
    h_2_eval_4n.push(h_2_eval_4n[3]);

    // Compute 4n evaluations of the wire polynomials
    let mut wl_eval_4n = domain_4n.coset_fft(&w_l_poly);
    wl_eval_4n.push(wl_eval_4n[0]);
    wl_eval_4n.push(wl_eval_4n[1]);
    wl_eval_4n.push(wl_eval_4n[2]);
    wl_eval_4n.push(wl_eval_4n[3]);
    let mut wr_eval_4n = domain_4n.coset_fft(&w_r_poly);
    wr_eval_4n.push(wr_eval_4n[0]);
    wr_eval_4n.push(wr_eval_4n[1]);
    wr_eval_4n.push(wr_eval_4n[2]);
    wr_eval_4n.push(wr_eval_4n[3]);
    let wo_eval_4n = domain_4n.coset_fft(&w_o_poly);

    let mut w4_eval_4n = domain_4n.coset_fft(&w_4_poly);
    w4_eval_4n.push(w4_eval_4n[0]);
    w4_eval_4n.push(w4_eval_4n[1]);
    w4_eval_4n.push(w4_eval_4n[2]);
    w4_eval_4n.push(w4_eval_4n[3]);

    let t_1 = compute_circuit_satisfiability_equation(
        &domain,
        (
            range_challenge,
            logic_challenge,
            fixed_base_challenge,
            var_base_challenge,
            lookup_challenge,
        ),
        prover_key,
        (&wl_eval_4n, &wr_eval_4n, &wo_eval_4n, &w4_eval_4n),
        public_inputs_poly,
        zeta,
        &f_eval,
    );

    let t_2 = compute_permutation_checks(
        domain,
        prover_key,
        (&wl_eval_4n, &wr_eval_4n, &wo_eval_4n, &w4_eval_4n),
        &f_eval,
        &t_eval_4n,
        &h_1_eval_4n,
        &h_2_eval_4n,
        &z_eval_4n,
        &p_eval_4n,
        (alpha, beta, gamma, delta, epsilon),
    );

    let quotient: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let numerator = t_1[i] + t_2[i];
            let denominator = prover_key.v_h_coset_4n()[i];
            numerator * denominator.invert().unwrap()
        })
        .collect();

    Ok(Polynomial::from_coefficients_vec(
        domain_4n.coset_ifft(&quotient),
    ))
}

// Ensures that the circuit is satisfied
fn compute_circuit_satisfiability_equation(
    domain: &EvaluationDomain,
    (range_challenge, logic_challenge, fixed_base_challenge, var_base_challenge, lookup_challenge): (
        &BlsScalar,
        &BlsScalar,
        &BlsScalar,
        &BlsScalar,
        &BlsScalar,
    ),
    prover_key: &PlookupProverKey,
    (wl_eval_4n, wr_eval_4n, wo_eval_4n, w4_eval_4n): (
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
    ),
    pi_poly: &Polynomial,
    zeta: &BlsScalar,
    f_eval: &[BlsScalar],
) -> Vec<BlsScalar> {
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
    let pi_eval_4n = domain_4n.coset_fft(pi_poly);

    let t: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let wl = &wl_eval_4n[i];
            let wr = &wr_eval_4n[i];
            let wo = &wo_eval_4n[i];
            let w4 = &w4_eval_4n[i];
            let wl_next = &wl_eval_4n[i + 4];
            let wr_next = &wr_eval_4n[i + 4];
            let w4_next = &w4_eval_4n[i + 4];
            let pi = &pi_eval_4n[i];
            let f1 = &f_eval[i];

            let a = prover_key.arithmetic.compute_quotient_i(i, wl, wr, wo, w4);

            let b =
                prover_key
                    .range
                    .compute_quotient_i(i, range_challenge, wl, wr, wo, w4, w4_next);

            let c = prover_key.logic.compute_quotient_i(
                i,
                logic_challenge,
                &wl,
                &wl_next,
                &wr,
                &wr_next,
                &wo,
                &w4,
                &w4_next,
            );

            let d = prover_key.fixed_base.compute_quotient_i(
                i,
                fixed_base_challenge,
                &wl,
                &wl_next,
                &wr,
                &wr_next,
                &wo,
                &w4,
                &w4_next,
            );

            let e = prover_key.variable_base.compute_quotient_i(
                i,
                var_base_challenge,
                &wl,
                &wl_next,
                &wr,
                &wr_next,
                &wo,
                &w4,
                &w4_next,
            );

            let f =
                prover_key
                    .lookup
                    .compute_quotient_i(i, lookup_challenge, &wl, &wr, &wo, f1, &zeta);

            (a + pi) + b + c + d + e + f
        })
        .collect();
    t
}

fn compute_permutation_checks(
    domain: &EvaluationDomain,
    prover_key: &PlookupProverKey,
    (wl_eval_4n, wr_eval_4n, wo_eval_4n, w4_eval_4n): (
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
    ),
    f_eval: &[BlsScalar],
    t_eval_4n: &[BlsScalar],
    h_1_eval_4n: &[BlsScalar],
    h_2_eval_4n: &[BlsScalar],
    z_eval_4n: &[BlsScalar],
    p_eval_4n: &[BlsScalar],
    (alpha, beta, gamma, delta, epsilon): (
        &BlsScalar,
        &BlsScalar,
        &BlsScalar,
        &BlsScalar,
        &BlsScalar,
    ),
) -> Vec<BlsScalar> {
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
    let l1_poly_alpha = compute_first_lagrange_poly_scaled(domain, alpha.square());
    let l1_alpha_sq_evals = domain_4n.coset_fft(&l1_poly_alpha.coeffs);

    let alpha_4 = alpha * alpha * alpha * alpha;
    let l1_poly_alpha_4 = compute_first_lagrange_poly_scaled(domain, alpha_4);
    let l1_alpha_4_evals = domain_4n.coset_fft(&l1_poly_alpha_4.coeffs);

    let alpha_6 = alpha_4 * alpha * alpha;
    let ln_poly_alpha_6 = compute_last_lagrange_poly_scaled(domain, alpha_6);
    let ln_alpha_6_evals = domain_4n.coset_fft(&ln_poly_alpha_6.coeffs);

    let alpha_7 = alpha_4 * alpha * alpha * alpha;
    let ln_poly_alpha_7 = compute_last_lagrange_poly_scaled(domain, alpha_7);
    let ln_alpha_7_evals = domain_4n.coset_fft(&ln_poly_alpha_7.coeffs);

    let t: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            prover_key.permutation.compute_plookup_quotient_i(
                i,
                &wl_eval_4n[i],
                &wr_eval_4n[i],
                &wo_eval_4n[i],
                &w4_eval_4n[i],
                &f_eval[i],
                &t_eval_4n[i],
                &t_eval_4n[i + 4],
                &h_1_eval_4n[i],
                &h_2_eval_4n[i],
                &h_1_eval_4n[i + 4],
                &h_2_eval_4n[i + 4],
                &z_eval_4n[i],
                &z_eval_4n[i + 4],
                &p_eval_4n[i],
                &p_eval_4n[i + 4],
                &alpha,
                &l1_alpha_sq_evals[i],
                &l1_alpha_4_evals[i],
                &ln_alpha_6_evals[i],
                &ln_alpha_7_evals[i],
                &beta,
                &gamma,
                &delta,
                &epsilon,
            )
        })
        .collect();
    t
}
fn compute_first_lagrange_poly_scaled(domain: &EvaluationDomain, scale: BlsScalar) -> Polynomial {
    let mut x_evals = vec![BlsScalar::zero(); domain.size()];
    x_evals[0] = scale;
    domain.ifft_in_place(&mut x_evals);
    Polynomial::from_coefficients_vec(x_evals)
}

fn compute_last_lagrange_poly_scaled(domain: &EvaluationDomain, scale: BlsScalar) -> Polynomial {
    let mut x_evals = vec![BlsScalar::zero(); domain.size()];
    x_evals[domain.size() - 1] = scale;
    domain.ifft_in_place(&mut x_evals);
    Polynomial::from_coefficients_vec(x_evals)
}
