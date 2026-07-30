// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
#[cfg(feature = "std")]
use rayon::prelude::*;

use crate::error::Error;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::ProverKey;

/// Computes the Quotient [`Polynomial`] given the [`EvaluationDomain`], a
/// [`ProverKey`] and some other info.
pub(crate) fn compute(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    z_poly: &Polynomial,
    (a_poly, b_poly, c_poly, d_poly): (
        &Polynomial,
        &Polynomial,
        &Polynomial,
        &Polynomial,
    ),
    public_inputs_poly: &Polynomial,
    (
        alpha,
        beta,
        gamma,
        range_challenge,
        logic_challenge,
        fixed_base_challenge,
        var_base_challenge,
    ): &(
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
    ),
) -> Result<Polynomial, Error> {
    // Compute 8n evals
    let domain_8n = EvaluationDomain::new(8 * domain.size())?;

    let mut z_eval_8n = domain_8n.coset_fft(z_poly);

    let mut a_eval_8n = domain_8n.coset_fft(a_poly);
    let mut b_eval_8n = domain_8n.coset_fft(b_poly);
    let c_eval_8n = domain_8n.coset_fft(c_poly);
    let mut d_eval_8n = domain_8n.coset_fft(d_poly);

    for i in 0..8 {
        z_eval_8n.push(z_eval_8n[i]);
        a_eval_8n.push(a_eval_8n[i]);
        b_eval_8n.push(b_eval_8n[i]);
        // c_eval_8n push not required
        d_eval_8n.push(d_eval_8n[i]);
    }

    let t_1 = compute_circuit_satisfiability_equation(
        domain,
        (
            range_challenge,
            logic_challenge,
            fixed_base_challenge,
            var_base_challenge,
        ),
        prover_key,
        (&a_eval_8n, &b_eval_8n, &c_eval_8n, &d_eval_8n),
        public_inputs_poly,
    );

    let t_2 = compute_permutation_checks(
        domain,
        prover_key,
        (&a_eval_8n, &b_eval_8n, &c_eval_8n, &d_eval_8n),
        &z_eval_8n,
        (alpha, beta, gamma),
    );

    #[cfg(not(feature = "std"))]
    let range = (0..domain_8n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_8n.size()).into_par_iter();

    let quotient: Vec<_> = range
        .map(|i| {
            let numerator = t_1[i] + t_2[i];
            let denominator = prover_key.v_h_coset_8n()[i];
            numerator * denominator.invert().unwrap()
        })
        .collect();

    let coset = domain_8n.coset_ifft(&quotient);
    let quotient_poly = Polynomial::from_coefficients_vec(coset);

    // A satisfied assignment yields a numerator divisible by the vanishing
    // polynomial of the domain, and the quotient's degree is bounded by the
    // numerator's: the permutation product z(x) (degree n + 2, with hiding
    // degree 2) times the four wire factors (degree n + 1 each, with hiding
    // degree 1) has degree 5n + 6, and every gate identity stays below that.
    // Dividing by the vanishing polynomial (degree n) leaves at most 4n + 6.
    //
    // An unsatisfied assignment leaves a nonzero remainder r(x) with
    // deg r < n. On the 8n-sized coset the pointwise division then computes
    // q(x) + r(x)/z_H(x), and 1/z_H interpolates over that coset to
    // c_0 + c_1·x^n + ... + c_7·x^7n with c_7 nonzero (z_H only takes 8
    // distinct values there), pushing the interpolated result to a degree of
    // at least 7n. The check is anchored on that detection floor rather than
    // the honest ceiling, so it stays correct should blinding or a new gate
    // ever push the honest quotient past 4n + 6 — up to 7n of headroom.
    // Unsatisfied assignments are caught even when the commit key is roomy
    // enough (small circuits, deserialized oversized keys) that the split
    // quotient chunks would have committed fine and only failed at
    // verification.
    //
    // `from_coefficients_vec` trims trailing zero coefficients, so the
    // coefficient vector is either empty or ends on a non-zero coefficient
    // and `len() == degree + 1`. Comparing lengths therefore reads the
    // degree in constant time instead of rescanning the coefficients, and
    // `degree() >= 7n` becomes `len() > 7n` (the empty polynomial passes
    // either way).
    if quotient_poly.len() > 7 * domain.size() {
        return Err(Error::CircuitUnsatisfied);
    }

    Ok(quotient_poly)
}

// Ensures that the circuit is satisfied
fn compute_circuit_satisfiability_equation(
    domain: &EvaluationDomain,
    (
        range_challenge,
        logic_challenge,
        fixed_base_challenge,
        var_base_challenge,
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    prover_key: &ProverKey,
    (a_eval_8n, b_eval_8n, c_eval_8n, d_eval_8n): (
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
    ),
    pi_poly: &Polynomial,
) -> Vec<BlsScalar> {
    let domain_8n = EvaluationDomain::new(8 * domain.size()).unwrap();
    let public_eval_8n = domain_8n.coset_fft(pi_poly);

    #[cfg(not(feature = "std"))]
    let range = (0..domain_8n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_8n.size()).into_par_iter();

    let t: Vec<_> = range
        .map(|i| {
            let a = &a_eval_8n[i];
            let b = &b_eval_8n[i];
            let c = &c_eval_8n[i];
            let d = &d_eval_8n[i];
            let a_w = &a_eval_8n[i + 8];
            let b_w = &b_eval_8n[i + 8];
            let d_w = &d_eval_8n[i + 8];
            let pi = &public_eval_8n[i];

            let t_arith =
                prover_key.arithmetic.compute_quotient_i(i, a, b, c, d);

            let t_range = prover_key.range.compute_quotient_i(
                i,
                range_challenge,
                a,
                b,
                c,
                d,
                d_w,
            );

            let t_logic = prover_key.logic.compute_quotient_i(
                i,
                logic_challenge,
                a,
                a_w,
                b,
                b_w,
                c,
                d,
                d_w,
            );

            let t_fixed = prover_key.fixed_base.compute_quotient_i(
                i,
                fixed_base_challenge,
                a,
                a_w,
                b,
                b_w,
                c,
                d,
                d_w,
            );

            let t_var = prover_key.variable_base.compute_quotient_i(
                i,
                var_base_challenge,
                a,
                a_w,
                b,
                b_w,
                c,
                d,
                d_w,
            );

            // Multiplication by selectors and challenges
            // has already been done
            t_arith + t_range + t_logic + t_fixed + t_var + pi
        })
        .collect();
    t
}

fn compute_permutation_checks(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    (a_eval_8n, b_eval_8n, c_eval_8n, d_eval_8n): (
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
    ),
    z_eval_8n: &[BlsScalar],
    (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
) -> Vec<BlsScalar> {
    let domain_8n = EvaluationDomain::new(8 * domain.size()).unwrap();
    let l1_poly_alpha =
        compute_first_lagrange_poly_scaled(domain, alpha.square());
    let l1_alpha_sq_evals = domain_8n.coset_fft(&l1_poly_alpha);

    #[cfg(not(feature = "std"))]
    let range = (0..domain_8n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_8n.size()).into_par_iter();

    let t: Vec<_> = range
        .map(|i| {
            prover_key.permutation.compute_quotient_i(
                i,
                &a_eval_8n[i],
                &b_eval_8n[i],
                &c_eval_8n[i],
                &d_eval_8n[i],
                &z_eval_8n[i],
                &z_eval_8n[i + 8],
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
