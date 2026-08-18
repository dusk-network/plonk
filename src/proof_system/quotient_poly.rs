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
use crate::util::batch_inversion;

/// Computes the Quotient [`Polynomial`] given the [`EvaluationDomain`], a
/// [`ProverKey`] and some other info.
pub(crate) fn compute(
    quotient_domain: &EvaluationDomain,
    prover_key: &ProverKey,
    z_poly: &Polynomial,
    (a_poly, b_poly, c_poly, d_poly): (
        &Polynomial,
        &Polynomial,
        &Polynomial,
        &Polynomial,
    ),
    public_inputs_poly: &Polynomial,
    vanishing_coset_inverses: &[BlsScalar; 8],
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
    let [
        mut z_eval_8n,
        mut a_eval_8n,
        mut b_eval_8n,
        c_eval_8n,
        mut d_eval_8n,
    ] = compute_coset_evaluations(
        quotient_domain,
        [z_poly, a_poly, b_poly, c_poly, d_poly],
    );

    for i in 0..8 {
        z_eval_8n.push(z_eval_8n[i]);
        a_eval_8n.push(a_eval_8n[i]);
        b_eval_8n.push(b_eval_8n[i]);
        // c_eval_8n push not required
        d_eval_8n.push(d_eval_8n[i]);
    }

    let t_1 = compute_circuit_satisfiability_equation(
        quotient_domain,
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
        quotient_domain,
        prover_key,
        (&a_eval_8n, &b_eval_8n, &c_eval_8n, &d_eval_8n),
        &z_eval_8n,
        (alpha, beta, gamma),
    );

    #[cfg(not(feature = "std"))]
    let range = (0..quotient_domain.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..quotient_domain.size()).into_par_iter();

    let quotient: Vec<_> = range
        .map(|i| {
            let numerator = t_1[i] + t_2[i];
            numerator * vanishing_coset_inverses[i & 7]
        })
        .collect();

    let coset = quotient_domain.coset_ifft(&quotient);
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
    if quotient_poly.len() > 7 * (quotient_domain.size() / 8) {
        return Err(Error::CircuitUnsatisfied);
    }

    Ok(quotient_poly)
}

fn compute_coset_evaluations(
    domain: &EvaluationDomain,
    polynomials: [&Polynomial; 5],
) -> [Vec<BlsScalar>; 5] {
    #[cfg(not(feature = "std"))]
    let evaluations = polynomials.map(|poly| domain.coset_fft(poly));

    #[cfg(feature = "std")]
    let evaluations = {
        let mut evaluations: [Vec<BlsScalar>; 5] = Default::default();
        evaluations
            .par_iter_mut()
            .zip(&polynomials[..])
            .for_each(|(slot, poly)| *slot = domain.coset_fft(poly));
        evaluations
    };

    evaluations
}

// Ensures that the circuit is satisfied
fn compute_circuit_satisfiability_equation(
    quotient_domain: &EvaluationDomain,
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
    let public_eval_8n = quotient_domain.coset_fft(pi_poly);

    #[cfg(not(feature = "std"))]
    let range = (0..quotient_domain.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..quotient_domain.size()).into_par_iter();

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
    quotient_domain: &EvaluationDomain,
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
    let l1_alpha_sq = alpha.square();
    let mut first_lagrange_coset_evaluations: Vec<_> = prover_key
        .permutation
        .linear_evaluations
        .evals
        .iter()
        .map(|evaluation| *evaluation - BlsScalar::one())
        .collect();
    batch_inversion(&mut first_lagrange_coset_evaluations);

    // The quotient domain has size 8n, while L1 is defined over the n-sized
    // proving domain: L1(x) = (x^n - 1) / (n * (x - 1)).
    let proving_domain_size_inv =
        quotient_domain.size_inv * BlsScalar::from(8u64);
    first_lagrange_coset_evaluations
        .iter_mut()
        .zip(&prover_key.v_h_coset_8n().evals)
        .for_each(|(denominator_inv, vanishing)| {
            *denominator_inv *= vanishing * proving_domain_size_inv;
        });

    #[cfg(not(feature = "std"))]
    let range = (0..quotient_domain.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..quotient_domain.size()).into_par_iter();

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
                &(first_lagrange_coset_evaluations[i] * l1_alpha_sq),
                beta,
                gamma,
            )
        })
        .collect();
    t
}
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn coset_evaluations_preserve_input_order_across_nested_rayon_pools() {
        let domain = EvaluationDomain::new(1 << 12).unwrap();
        let polynomials = core::array::from_fn(|index| {
            Polynomial::from_coefficients_vec(
                (0..domain.size())
                    .map(|coefficient| {
                        BlsScalar::from(
                            (index * domain.size() + coefficient + 1) as u64,
                        )
                    })
                    .collect(),
            )
        });
        let reference_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let expected = reference_pool.install(|| {
            polynomials.each_ref().map(|poly| domain.coset_fft(poly))
        });

        for threads in [8, 9] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let actual = pool.install(|| {
                compute_coset_evaluations(&domain, polynomials.each_ref())
            });

            assert_eq!(actual, expected, "failed with {threads} threads");
        }
    }
}
