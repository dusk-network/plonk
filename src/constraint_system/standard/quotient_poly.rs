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
        preprocessed_circuit.q4_eval_4n(),
        preprocessed_circuit.qarith_eval_4n(),
        preprocessed_circuit.qrange_eval_4n(),
        preprocessed_circuit.qlogic_eval_4n(),
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

    let t_4 =
        grand_product_quotient::compute_is_one_polynomial(domain, z_poly, alpha.square() * alpha);

    let quotient: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let numerator = t_2[i] + t_3[i] + t_4[i];
            let denominator = preprocessed_circuit.v_h_coset_4n()[i];
            t_1[i] + (numerator * denominator.invert().unwrap())
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
    q4_eval_4n: &Evaluations,
    qarith_eval_4n: &Evaluations,
    qrange_eval_4n: &Evaluations,
    qlogic_eval_4n: &Evaluations,
    pi_poly: &Polynomial,
    wl_poly: &Polynomial,
    wr_poly: &Polynomial,
    wo_poly: &Polynomial,
    w4_poly: &Polynomial,
) -> Evaluations {
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();

    // Computes f(f-1)(f-2)(f-3)
    let delta = |f: Scalar| -> Scalar {
        let f_1 = f - Scalar::one();
        let f_2 = f - Scalar::from(2);
        let f_3 = f - Scalar::from(3);
        f * f_1 * f_2 * f_3
    };
    let four = Scalar::from(4);

    let pi_eval_4n = domain_4n.coset_fft(pi_poly);
    let wl_eval_4n = domain_4n.coset_fft(&wl_poly);
    let wr_eval_4n = domain_4n.coset_fft(&wr_poly);
    let wo_eval_4n = domain_4n.coset_fft(&wo_poly);
    let mut w4_eval_4n = domain_4n.coset_fft(&w4_poly);
    w4_eval_4n.push(w4_eval_4n[0]);
    w4_eval_4n.push(w4_eval_4n[1]);
    w4_eval_4n.push(w4_eval_4n[2]);
    w4_eval_4n.push(w4_eval_4n[3]);

    let v_h = domain_4n.compute_vanishing_poly_over_coset(domain.size() as u64);

    let t_1: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let wl = &wl_eval_4n[i];
            let wr = &wr_eval_4n[i];
            let wo = &wo_eval_4n[i];
            let w4 = &w4_eval_4n[i];
            let w4_next = &w4_eval_4n[i + 4];
            let qm = &qm_eval_4n[i];
            let ql = &ql_eval_4n[i];
            let qr = &qr_eval_4n[i];
            let qo = &qo_eval_4n[i];
            let q4 = &q4_eval_4n[i];
            let qc = &qc_eval_4n[i];
            let pi = &pi_eval_4n[i];
            let qarith = &qarith_eval_4n[i];
            let qrange = &qrange_eval_4n[i];
            let qlogic = &qlogic_eval_4n[i];
            let v_h_i = v_h[i].invert().unwrap();
            // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + d(x)q_4(X) + PI(X) + Q_C(X)) * Q_Arith(X)
            //
            let a_1 = wl * wr * qm;
            let a_2 = wl * ql;
            let a_3 = wr * qr;
            let a_4 = wo * qo;
            let a_5 = w4 * q4;
            let a_6 = qc + pi;
            let a = (a_1 + a_2 + a_3 + a_4 + a_5 + a_6) * qarith;

            // Delta([c(X) - 4 * d(X)]) + Delta([b(X) - 4 * c(X)]) + Delta([a(X) - 4 * b(X)]) + Delta([d(Xg) - 4 * a(X)]) * Q_Range(X)
            //
            let b_1 = delta(wo - four * w4);
            let b_2 = delta(wr - four * wo);
            let b_3 = delta(wl - four * wr);
            let b_4 = delta(w4_next - four * wl);
            let b = (b_1 + b_2 + b_3 + b_4) * qrange;

            // XXX: Carlos
            let c = qlogic * ((wl - wr) * wo);

            (a + b + c) * alpha * v_h_i
        })
        .collect();
    Evaluations::from_vec_and_domain(t_1, domain_4n)
}
