/// This quotient polynomial can only be used for the standard composer
/// Each composer will need to implement their own method for computing the quotient polynomial
use crate::constraint_system::standard::PreProcessedCircuit;

use crate::fft::Evaluations;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::permutation::grand_product_quotient;
use bls12_381::Scalar;
use rayon::prelude::*;

/// Computes the quotient polynomial
pub(crate) fn compute(
    domain: &EvaluationDomain,
    preprocessed_circuit: &PreProcessedCircuit,
    z_poly: &Polynomial,
    witness_polynomials: [&Polynomial; 4],
    public_inputs_poly: &Polynomial,
    (alpha, beta, gamma): &(Scalar, Scalar, Scalar),
) -> Polynomial {
    let w_l_poly = witness_polynomials[0];
    let w_r_poly = witness_polynomials[1];
    let w_o_poly = witness_polynomials[2];
    let w_4_poly = witness_polynomials[3];

    // Compute 4n eval of z(X)
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
    let mut z_eval_4n = domain_4n.coset_fft(&z_poly);
    z_eval_4n.push(z_eval_4n[0]);
    z_eval_4n.push(z_eval_4n[1]);
    z_eval_4n.push(z_eval_4n[2]);
    z_eval_4n.push(z_eval_4n[3]);

    let t_1 = compute_circuit_satisfiability_equation(
        domain,
        alpha,
        preprocessed_circuit.qm_eval_4n(),
        preprocessed_circuit.ql_eval_4n(),
        preprocessed_circuit.qr_eval_4n(),
        preprocessed_circuit.qo_eval_4n(),
        preprocessed_circuit.qc_eval_4n(),
        public_inputs_poly,
        w_l_poly,
        w_r_poly,
        w_o_poly,
        w_4_poly,
    );

    let t_2 = grand_product_quotient::compute_identity_polynomial(
        domain,
        &alpha.square(),
        beta,
        gamma,
        &z_eval_4n,
        &w_l_poly,
        &w_r_poly,
        &w_o_poly,
        &w_4_poly,
    );
    let t_3 = grand_product_quotient::compute_copy_polynomial(
        domain,
        &alpha.square(),
        beta,
        gamma,
        &z_eval_4n,
        &w_l_poly,
        &w_r_poly,
        &w_o_poly,
        &w_4_poly,
        preprocessed_circuit.left_sigma_poly(),
        preprocessed_circuit.right_sigma_poly(),
        preprocessed_circuit.out_sigma_poly(),
        preprocessed_circuit.fourth_sigma_poly(),
    );

    let t_4 = grand_product_quotient::compute_is_one_polynomial(
        domain,
        z_poly,
        &(alpha.square() * alpha),
    );
    // Compute 4n evaluations for X^n -1
    let v_h_coset_4n = domain_4n.compute_vanishing_poly_over_coset(domain.size() as u64);

    // XXX: We can compute the 4n evaluations for the vanishing polynomial in the preprocessing stage
    let quotient: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let numerator = t_1[i] + t_2[i] + t_3[i] + t_4[i];
            let denominator = v_h_coset_4n[i];
            numerator * denominator.invert().unwrap()
        })
        .collect();

    Polynomial::from_coefficients_vec(domain_4n.coset_ifft(&quotient))
}

// Ensures that the circuit is satisfied
fn compute_circuit_satisfiability_equation(
    domain: &EvaluationDomain,
    alpha: &Scalar,
    qm_eval_4n: &Evaluations,
    ql_eval_4n: &Evaluations,
    qr_eval_4n: &Evaluations,
    qo_eval_4n: &Evaluations,
    qc_eval_4n: &Evaluations,
    pi_poly: &Polynomial,
    wl_poly: &Polynomial,
    wr_poly: &Polynomial,
    wo_poly: &Polynomial,
    w4_poly: &Polynomial,
) -> Evaluations {
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();

    let pi_eval_4n = domain_4n.coset_fft(pi_poly);
    let wl_eval_4n = domain_4n.coset_fft(&wl_poly);
    let wr_eval_4n = domain_4n.coset_fft(&wr_poly);
    let wo_eval_4n = domain_4n.coset_fft(&wo_poly);
    let w4_eval_4n = domain_4n.coset_fft(&w4_poly);

    let t_1: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let wl = &wl_eval_4n[i];
            let wr = &wr_eval_4n[i];
            let wo = &wo_eval_4n[i];
            let w4 = &w4_eval_4n[i];
            let qm = &qm_eval_4n[i];
            let ql = &ql_eval_4n[i];
            let qr = &qr_eval_4n[i];
            let qo = &qo_eval_4n[i];
            let qc = &qc_eval_4n[i];
            let pi = &pi_eval_4n[i];
            // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + d(x) + PI(X) + Q_C(X))
            //
            //(a(x)b(x)q_M(x)
            let mut a_1 = wl * wr;
            a_1 = a_1 * qm;
            //a(x)q_L(x)
            let a_2 = wl * ql;
            //b(X)q_R(x)
            let a_3 = wr * qr;
            //c(X)q_O(X)
            let a_4 = wo * qo;
            // d(x)
            let a_5 = w4;
            // q_C(x) + PI(X)
            let a_6 = qc + pi;
            // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + d(X) + PI(X) + Q_C(X)) * alpha
            let mut a = a_1 + a_2;
            a += a_3;
            a += a_4;
            a += a_5;
            a += a_6;
            a = a * alpha;
            a
        })
        .collect();
    Evaluations::from_vec_and_domain(t_1, domain_4n)
}
