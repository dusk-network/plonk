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
    (a_w_poly, b_w_poly, c_w_poly, d_w_poly): (
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

    let mut a_w_eval_8n = domain_8n.coset_fft(a_w_poly);
    let mut b_w_eval_8n = domain_8n.coset_fft(b_w_poly);
    let c_w_eval_8n = domain_8n.coset_fft(c_w_poly);
    let mut d_w_eval_8n = domain_8n.coset_fft(d_w_poly);

    for i in 0..8 {
        z_eval_8n.push(z_eval_8n[i]);
        a_w_eval_8n.push(a_w_eval_8n[i]);
        b_w_eval_8n.push(b_w_eval_8n[i]);
        // c_w_eval_8n push not required
        d_w_eval_8n.push(d_w_eval_8n[i]);
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
        (&a_w_eval_8n, &b_w_eval_8n, &c_w_eval_8n, &d_w_eval_8n),
        public_inputs_poly,
    );

    let t_2 = compute_permutation_checks(
        domain,
        prover_key,
        (&a_w_eval_8n, &b_w_eval_8n, &c_w_eval_8n, &d_w_eval_8n),
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
    let mut num_zeroes_in_coset = 0;
    for x in coset.iter() {
        if x.0[0] == 0u64 && x.0[1] == 0u64 && x.0[2] == 0u64 && x.0[3] == 0u64 {
            num_zeroes_in_coset += 1;
        }
    }

    let p = Polynomial::from_coefficients_vec(coset.clone());

    #[cfg(feature = "debug")]
    println!("plonk: coset size={} p degree={} num_zeroes in coset={}", coset.len(), p.degree(), num_zeroes_in_coset);
    Ok(p)
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
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    prover_key: &ProverKey,
    (a_w_eval_8n, b_w_eval_8n, c_w_eval_8n, d_w_eval_8n): (
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
            let a_w = &a_w_eval_8n[i];
            let b_w = &b_w_eval_8n[i];
            let c_w = &c_w_eval_8n[i];
            let d_w = &d_w_eval_8n[i];
            let a_w_next = &a_w_eval_8n[i + 8];
            let b_w_next = &b_w_eval_8n[i + 8];
            let d_w_next = &d_w_eval_8n[i + 8];
            let pi = &public_eval_8n[i];

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

            (a + pi) + b + c + d + e
        })
        .collect();
    t
}

fn compute_permutation_checks(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    (a_w_eval_8n, b_w_eval_8n, c_w_eval_8n, d_w_eval_8n): (
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
    let l1_alpha_sq_evals = domain_8n.coset_fft(&l1_poly_alpha.coeffs);

    #[cfg(not(feature = "std"))]
    let range = (0..domain_8n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_8n.size()).into_par_iter();

    let t: Vec<_> = range
        .map(|i| {
            prover_key.permutation.compute_quotient_i(
                i,
                &a_w_eval_8n[i],
                &b_w_eval_8n[i],
                &c_w_eval_8n[i],
                &d_w_eval_8n[i],
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
