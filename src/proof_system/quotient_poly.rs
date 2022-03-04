// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{
    error::Error,
    fft::{EvaluationDomain, Polynomial},
    proof_system::ProverKey,
};
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
#[cfg(feature = "std")]
use rayon::prelude::*;

/// Computes the Quotient [`Polynomial`] given the [`EvaluationDomain`], a
/// [`ProverKey`] and some other info.
pub(crate) fn compute(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    z_poly: &Polynomial,
    p_poly: &Polynomial,
    (a_w_poly, b_w_poly, c_w_poly, d_w_poly): (
        &Polynomial,
        &Polynomial,
        &Polynomial,
        &Polynomial,
    ),
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
    let mut z_eval_4n = domain_4n.coset_fft(z_poly);
    z_eval_4n.push(z_eval_4n[0]);
    z_eval_4n.push(z_eval_4n[1]);
    z_eval_4n.push(z_eval_4n[2]);
    z_eval_4n.push(z_eval_4n[3]);

    // Compute 4n eval of p(X)
    let mut p_eval_4n = domain_4n.coset_fft(p_poly);
    p_eval_4n.push(p_eval_4n[0]);
    p_eval_4n.push(p_eval_4n[1]);
    p_eval_4n.push(p_eval_4n[2]);
    p_eval_4n.push(p_eval_4n[3]);

    // Compute 4n evals of table poly, t(x)
    let mut t_eval_4n = domain_4n.coset_fft(t_poly);
    t_eval_4n.push(t_eval_4n[0]);
    t_eval_4n.push(t_eval_4n[1]);
    t_eval_4n.push(t_eval_4n[2]);
    t_eval_4n.push(t_eval_4n[3]);

    // Compute f(x)
    let f_eval_4n = domain_4n.coset_fft(f_poly);

    // Compute 4n eval of h_1
    let mut h_1_eval_4n = domain_4n.coset_fft(h_1_poly);
    h_1_eval_4n.push(h_1_eval_4n[0]);
    h_1_eval_4n.push(h_1_eval_4n[1]);
    h_1_eval_4n.push(h_1_eval_4n[2]);
    h_1_eval_4n.push(h_1_eval_4n[3]);

    // Compute 4n eval of h_2
    let mut h_2_eval_4n = domain_4n.coset_fft(h_2_poly);
    h_2_eval_4n.push(h_2_eval_4n[0]);
    h_2_eval_4n.push(h_2_eval_4n[1]);
    h_2_eval_4n.push(h_2_eval_4n[2]);
    h_2_eval_4n.push(h_2_eval_4n[3]);

    // Compute 4n evaluations of the wire polynomials
    let mut a_w_eval_4n = domain_4n.coset_fft(a_w_poly);
    a_w_eval_4n.push(a_w_eval_4n[0]);
    a_w_eval_4n.push(a_w_eval_4n[1]);
    a_w_eval_4n.push(a_w_eval_4n[2]);
    a_w_eval_4n.push(a_w_eval_4n[3]);
    let mut b_w_eval_4n = domain_4n.coset_fft(b_w_poly);
    b_w_eval_4n.push(b_w_eval_4n[0]);
    b_w_eval_4n.push(b_w_eval_4n[1]);
    b_w_eval_4n.push(b_w_eval_4n[2]);
    b_w_eval_4n.push(b_w_eval_4n[3]);
    let c_w_eval_4n = domain_4n.coset_fft(c_w_poly);

    let mut d_w_eval_4n = domain_4n.coset_fft(d_w_poly);
    d_w_eval_4n.push(d_w_eval_4n[0]);
    d_w_eval_4n.push(d_w_eval_4n[1]);
    d_w_eval_4n.push(d_w_eval_4n[2]);
    d_w_eval_4n.push(d_w_eval_4n[3]);

    let t_1 = compute_circuit_satisfiability_equation(
        domain,
        (
            range_challenge,
            logic_challenge,
            fixed_base_challenge,
            var_base_challenge,
            lookup_challenge,
        ),
        prover_key,
        (&a_w_eval_4n, &b_w_eval_4n, &c_w_eval_4n, &d_w_eval_4n),
        public_inputs_poly,
        zeta,
        (delta, epsilon),
        &f_eval_4n,
        &p_eval_4n,
        &t_eval_4n,
        &h_1_eval_4n,
        &h_2_eval_4n,
    );

    let t_2 = compute_permutation_checks(
        domain,
        prover_key,
        (&a_w_eval_4n, &b_w_eval_4n, &c_w_eval_4n, &d_w_eval_4n),
        &z_eval_4n,
        (alpha, beta, gamma),
    );

    #[cfg(not(feature = "std"))]
    let range = (0..domain_4n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_4n.size()).into_par_iter();

    let quotient: Vec<_> = range
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
// Ensures that the circuit is satisfied
fn compute_circuit_satisfiability_equation(
    domain: &EvaluationDomain,
    (
        range_challenge,
        logic_challenge,
        fixed_base_challenge,
        var_base_challenge,
        lookup_challenge,
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    prover_key: &ProverKey,
    (a_w_eval_4n, b_w_eval_4n, c_w_eval_4n, d_w_eval_4n): (
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
    ),
    pi_poly: &Polynomial,
    zeta: &BlsScalar,
    (delta, epsilon): (&BlsScalar, &BlsScalar),
    f_eval_4n: &[BlsScalar],
    p_eval_4n: &[BlsScalar],
    t_eval_4n: &[BlsScalar],
    h_1_eval_4n: &[BlsScalar],
    h_2_eval_4n: &[BlsScalar],
) -> Vec<BlsScalar> {
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
    let public_eval_4n = domain_4n.coset_fft(pi_poly);

    let l1_eval_4n = domain_4n.coset_fft(&compute_first_lagrange_poly_scaled(
        domain,
        BlsScalar::one(),
    ));

    #[cfg(not(feature = "std"))]
    let range = (0..domain_4n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_4n.size()).into_par_iter();

    let t: Vec<_> = range
        .map(|i| {
            let a_w = &a_w_eval_4n[i];
            let b_w = &b_w_eval_4n[i];
            let c_w = &c_w_eval_4n[i];
            let d_w = &d_w_eval_4n[i];
            let a_w_next = &a_w_eval_4n[i + 4];
            let b_w_next = &b_w_eval_4n[i + 4];
            let d_w_next = &d_w_eval_4n[i + 4];
            let pi = &public_eval_4n[i];
            let p = &p_eval_4n[i];
            let p_next = &p_eval_4n[i + 4];
            let fi = &f_eval_4n[i];
            let ti = &t_eval_4n[i];
            let ti_next = &t_eval_4n[i + 4];
            let h1 = &h_1_eval_4n[i];
            let h2 = &h_2_eval_4n[i];
            let h1_next = &h_1_eval_4n[i + 4];
            let l1i = &l1_eval_4n[i];

            let a = prover_key
                .arithmetic
                .compute_quotient_i(i, a_w, b_w, c_w, d_w);

            let b = prover_key.range.compute_quotient_i(
                i,
                range_challenge,
                a_w,
                b_w,
                c_w,
                d_w,
                d_w_next,
            );

            let c = prover_key.logic.compute_quotient_i(
                i,
                logic_challenge,
                a_w,
                a_w_next,
                b_w,
                b_w_next,
                c_w,
                d_w,
                d_w_next,
            );

            let d = prover_key.fixed_base.compute_quotient_i(
                i,
                fixed_base_challenge,
                a_w,
                a_w_next,
                b_w,
                b_w_next,
                c_w,
                d_w,
                d_w_next,
            );

            let e = prover_key.variable_base.compute_quotient_i(
                i,
                var_base_challenge,
                a_w,
                a_w_next,
                b_w,
                b_w_next,
                c_w,
                d_w,
                d_w_next,
            );

            let f = prover_key.lookup.compute_quotient_i(
                i,
                lookup_challenge,
                a_w,
                b_w,
                c_w,
                d_w,
                fi,
                p,
                p_next,
                ti,
                ti_next,
                h1,
                h1_next,
                h2,
                l1i,
                (delta, epsilon),
                zeta,
            );

            (a + pi) + b + c + d + e + f
        })
        .collect();
    t
}

fn compute_permutation_checks(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    (a_w_eval_4n, b_w_eval_4n, c_w_eval_4n, d_w_eval_4n): (
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
    ),
    z_eval_4n: &[BlsScalar],
    (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
) -> Vec<BlsScalar> {
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
    let l1_poly_alpha =
        compute_first_lagrange_poly_scaled(domain, alpha.square());
    let l1_alpha_sq_evals = domain_4n.coset_fft(&l1_poly_alpha.coeffs);

    #[cfg(not(feature = "std"))]
    let range = (0..domain_4n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_4n.size()).into_par_iter();

    let t: Vec<_> = range
        .map(|i| {
            prover_key.permutation.compute_quotient_i(
                i,
                &a_w_eval_4n[i],
                &b_w_eval_4n[i],
                &c_w_eval_4n[i],
                &d_w_eval_4n[i],
                &z_eval_4n[i],
                &z_eval_4n[i + 4],
                alpha,
                &l1_alpha_sq_evals[i],
                beta,
                gamma,
            )
        })
        .collect();
    t
}
fn compute_first_lagrange_poly_scaled(
    domain: &EvaluationDomain,
    scale: BlsScalar,
) -> Polynomial {
    let mut x_evals = vec![BlsScalar::zero(); domain.size()];
    x_evals[0] = scale;
    domain.ifft_in_place(&mut x_evals);
    Polynomial::from_coefficients_vec(x_evals)
}
