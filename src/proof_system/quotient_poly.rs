use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::PreProcessedCircuit;
use dusk_bls12_381::Scalar;
use failure::Error;
use rayon::prelude::*;

/// This quotient polynomial can only be used for the standard composer
/// Each composer will need to implement their own method for computing the quotient polynomial

/// Computes the quotient polynomial
pub(crate) fn compute(
    domain: &EvaluationDomain,
    preprocessed_circuit: &PreProcessedCircuit,
    z_poly: &Polynomial,
    (w_l_poly, w_r_poly, w_o_poly, w_4_poly): (&Polynomial, &Polynomial, &Polynomial, &Polynomial),
    public_inputs_poly: &Polynomial,
    (alpha, beta, gamma, range_challenge, logic_challenge): &(
        Scalar,
        Scalar,
        Scalar,
        Scalar,
        Scalar,
    ),
) -> Result<Polynomial, Error> {
    // Compute 4n eval of z(X)
    let domain_4n = EvaluationDomain::new(4 * domain.size())?;
    let mut z_eval_4n = domain_4n.coset_fft(&z_poly);
    z_eval_4n.push(z_eval_4n[0]);
    z_eval_4n.push(z_eval_4n[1]);
    z_eval_4n.push(z_eval_4n[2]);
    z_eval_4n.push(z_eval_4n[3]);

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
        (range_challenge, logic_challenge),
        preprocessed_circuit,
        (&wl_eval_4n, &wr_eval_4n, &wo_eval_4n, &w4_eval_4n),
        public_inputs_poly,
    );

    let t_2 = compute_permutation_checks(
        domain,
        preprocessed_circuit,
        (&wl_eval_4n, &wr_eval_4n, &wo_eval_4n, &w4_eval_4n),
        &z_eval_4n,
        (alpha, beta, gamma),
    );

    let quotient: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let numerator = t_1[i] + t_2[i];
            let denominator = preprocessed_circuit.prover_key.v_h_coset_4n()[i];
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
    (range_challenge, logic_challenge): (&Scalar, &Scalar),
    preprocessed_circuit: &PreProcessedCircuit,
    (wl_eval_4n, wr_eval_4n, wo_eval_4n, w4_eval_4n): (&[Scalar], &[Scalar], &[Scalar], &[Scalar]),
    pi_poly: &Polynomial,
) -> Vec<Scalar> {
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

            let a = preprocessed_circuit
                .prover_key
                .arithmetic
                .compute_quotient_i(i, wl, wr, wo, w4);

            let b = preprocessed_circuit.prover_key.range.compute_quotient_i(
                i,
                range_challenge,
                wl,
                wr,
                wo,
                w4,
                w4_next,
            );

            let c = preprocessed_circuit.prover_key.logic.compute_quotient_i(
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

            (a + pi) + b + c
        })
        .collect();
    t
}

fn compute_permutation_checks(
    domain: &EvaluationDomain,
    preprocessed_circuit: &PreProcessedCircuit,
    (wl_eval_4n, wr_eval_4n, wo_eval_4n, w4_eval_4n): (&[Scalar], &[Scalar], &[Scalar], &[Scalar]),
    z_eval_4n: &[Scalar],
    (alpha, beta, gamma): (&Scalar, &Scalar, &Scalar),
) -> Vec<Scalar> {
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
    let l1_poly_alpha = compute_first_lagrange_poly_scaled(domain, alpha.square());
    let l1_alpha_sq_evals = domain_4n.coset_fft(&l1_poly_alpha.coeffs);

    let t: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            preprocessed_circuit
                .prover_key
                .permutation
                .compute_quotient_i(
                    i,
                    &wl_eval_4n[i],
                    &wr_eval_4n[i],
                    &wo_eval_4n[i],
                    &w4_eval_4n[i],
                    &z_eval_4n[i],
                    &z_eval_4n[i + 4],
                    &alpha,
                    &l1_alpha_sq_evals[i],
                    &beta,
                    &gamma,
                )
        })
        .collect();
    t
}
fn compute_first_lagrange_poly_scaled(domain: &EvaluationDomain, scale: Scalar) -> Polynomial {
    let mut x_evals = vec![Scalar::zero(); domain.size()];
    x_evals[0] = scale;
    domain.ifft_in_place(&mut x_evals);
    Polynomial::from_coefficients_vec(x_evals)
}
