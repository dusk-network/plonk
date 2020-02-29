use crate::constraint_system::standard::PreProcessedCircuit;

use crate::fft::Evaluations;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::permutation::constants::{K1, K2};
use bls12_381::Scalar;
use rayon::prelude::*;
pub fn compute(
    domain: &EvaluationDomain,
    preprocessed_circuit: &PreProcessedCircuit,
    z_poly: &Polynomial,
    witness_polynomials: [&Polynomial; 3],
    public_inputs_poly: &Polynomial,
    (alpha, beta, gamma): &(Scalar, Scalar, Scalar),
) -> Polynomial {
    let w_l_poly = witness_polynomials[0];
    let w_r_poly = witness_polynomials[1];
    let w_o_poly = witness_polynomials[2];

    // Compute components for t(X)
    let t_1 = compute_quotient_first_component(
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
    );

    // Compute 4n eval of z(X)
    let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
    let mut z_eval_4n = domain_4n.coset_fft(&z_poly);
    z_eval_4n.push(z_eval_4n[0]);
    z_eval_4n.push(z_eval_4n[1]);
    z_eval_4n.push(z_eval_4n[2]);
    z_eval_4n.push(z_eval_4n[3]);

    let t_2 = compute_quotient_second_component(
        domain,
        &alpha.square(),
        beta,
        gamma,
        &z_eval_4n,
        &w_l_poly,
        &w_r_poly,
        &w_o_poly,
    );
    let t_3 = compute_quotient_third_component(
        domain,
        &alpha.square(),
        beta,
        gamma,
        &z_eval_4n,
        &w_l_poly,
        &w_r_poly,
        &w_o_poly,
        preprocessed_circuit.left_sigma_poly(),
        preprocessed_circuit.right_sigma_poly(),
        preprocessed_circuit.out_sigma_poly(),
    );
    let t_4 = compute_quotient_fourth_component(domain, z_poly, alpha.square() * alpha);
    // Compute 4n evaluations for X^n -1
    let v_h_coset_4n = compute_vanishing_poly_over_coset(&domain_4n, domain.size() as u64);

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

fn compute_quotient_first_component(
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
) -> Evaluations {
    let n = domain.size();
    let domain_4n = EvaluationDomain::new(4 * n).unwrap();

    let pi_eval_4n = domain_4n.coset_fft(pi_poly);

    let wl_eval_4n = domain_4n.coset_fft(&wl_poly);
    let wr_eval_4n = domain_4n.coset_fft(&wr_poly);
    let wo_eval_4n = domain_4n.coset_fft(&wo_poly);

    let t_1: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let wl = &wl_eval_4n[i];
            let wr = &wr_eval_4n[i];
            let wo = &wo_eval_4n[i];

            let qm_alpha = &qm_eval_4n[i];
            let ql_alpha = &ql_eval_4n[i];
            let qr_alpha = &qr_eval_4n[i];
            let qo_alpha = &qo_eval_4n[i];
            let qc_alpha = &qc_eval_4n[i];
            let pi_alpha = &pi_eval_4n[i];

            // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + PI(X) + Q_C(X))
            //
            //(a(x)b(x)q_M(x)
            let mut a_1 = wl * wr;
            a_1 = a_1 * qm_alpha;
            //a(x)q_L(x)
            let a_2 = *wl * ql_alpha;
            //b(X)q_R(x)
            let a_3 = *wr * qr_alpha;
            //c(X)q_O(X)
            let a_4 = *wo * qo_alpha;
            // q_C(x) + PI(X)
            let a_5 = *qc_alpha + pi_alpha;

            // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + PI(X) + Q_C(X)) * alpha
            let mut a = a_1 + &a_2;
            a += &a_3;
            a += &a_4;
            a += &a_5;
            a = a * alpha;
            a
        })
        .collect();

    Evaluations::from_vec_and_domain(t_1, domain_4n)
}

fn compute_quotient_second_component(
    domain: &EvaluationDomain,
    alpha_sq: &Scalar,
    beta: &Scalar,
    gamma: &Scalar,
    z_eval_4n: &Vec<Scalar>,
    wl_coeffs: &Polynomial,
    wr_coeffs: &Polynomial,
    wo_coeffs: &Polynomial,
) -> Evaluations {
    let n = domain.size();
    let domain_4n = EvaluationDomain::new(4 * n).unwrap();

    // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)
    let mut a = wl_coeffs.to_vec();
    a[0] = a[0] + gamma;
    a[1] = a[1] + beta;

    let mut b = wr_coeffs.to_vec();
    b[0] = b[0] + gamma;
    let beta_k1 = *beta * K1;
    b[1] = b[1] + &beta_k1;

    let mut c = wo_coeffs.to_vec();
    c[0] = c[0] + gamma;
    let beta_k2 = *beta * K2;
    c[1] = c[1] + &beta_k2;

    domain_4n.coset_fft_in_place(&mut a);
    domain_4n.coset_fft_in_place(&mut b);
    domain_4n.coset_fft_in_place(&mut c);

    let t_2: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let z = &z_eval_4n[i];

            let mut product = a[i] * &b[i] * &c[i]; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)
            product = product * z; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)z(X) * alpha^2

            product * alpha_sq
        })
        .collect();
    Evaluations::from_vec_and_domain(t_2, domain_4n)
}

fn compute_quotient_third_component(
    domain: &EvaluationDomain,
    alpha_sq: &Scalar,
    beta: &Scalar,
    gamma: &Scalar,
    z_eval_4n: &Vec<Scalar>,
    wl_poly: &Polynomial,
    wr_poly: &Polynomial,
    wo_poly: &Polynomial,
    left_sigma_poly: &Polynomial,
    right_sigma_poly: &Polynomial,
    out_sigma_poly: &Polynomial,
) -> Evaluations {
    let n = domain.size();
    let domain_4n = EvaluationDomain::new(4 * n).unwrap();

    // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)
    //
    let beta_left_sigma = left_sigma_poly * beta;
    let beta_right_sigma = right_sigma_poly * beta;
    let beta_out_sigma = out_sigma_poly * beta;
    // (a(x) + beta * Sigma1(X) + gamma)
    //
    let mut a = &beta_left_sigma + wl_poly;
    a[0] = a[0] + gamma;
    // (b(X) + beta * Sigma2(X) + gamma)
    //
    let mut b = &beta_right_sigma + wr_poly;
    b[0] = b[0] + gamma;
    //(c(X) + beta * Sigma3(X) + gamma)
    //
    let mut c = &beta_out_sigma + wo_poly;
    c[0] = c[0] + gamma;

    let a_fft = domain_4n.coset_fft(&a);
    let b_fft = domain_4n.coset_fft(&b);
    let c_fft = domain_4n.coset_fft(&c);

    let t_3: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let z_shifted = &z_eval_4n[i + 4];

            let mut product = a_fft[i] * &b_fft[i] * &c_fft[i]; // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)
            product = product * z_shifted;

            -product * alpha_sq // (a(x) + beta* Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma) Z(X.omega) * alpha^2
        })
        .collect();

    Evaluations::from_vec_and_domain(t_3, domain_4n)
}

fn compute_quotient_fourth_component(
    domain: &EvaluationDomain,
    z_poly: &Polynomial,
    alpha_cu: Scalar,
) -> Evaluations {
    let n = domain.size();
    let domain_4n = EvaluationDomain::new(4 * n).unwrap();

    let l1_poly = compute_first_lagrange_poly(domain);
    let alpha_cu_l1_poly = &l1_poly * &alpha_cu;

    // (Z(x) - 1)
    let mut z_coeffs = z_poly.to_vec();
    z_coeffs[0] = z_coeffs[0] - &Scalar::one();

    let z_evals = domain_4n.coset_fft(&z_coeffs);
    let alpha_cu_l1_evals = domain_4n.coset_fft(&alpha_cu_l1_poly.coeffs);

    let t_4: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| alpha_cu_l1_evals[i] * &z_evals[i])
        .collect();
    Evaluations::from_vec_and_domain(t_4, domain_4n)
}

/// Computes the first Lagrange polynomial `L1(X)`.
fn compute_first_lagrange_poly(domain: &EvaluationDomain) -> Polynomial {
    let mut x_evals = vec![Scalar::zero(); domain.size()];
    x_evals[0] = Scalar::one();
    domain.ifft_in_place(&mut x_evals);
    Polynomial::from_coefficients_vec(x_evals)
}

// Computes the vanishing polynomial for that domain over a coset
// Z(x_i) = (x_i)^n -1  where x_i is the i'th root of unity
// Over coset Z(x_i *h) = (x_i *h)^n -1 = h^n * (x_i)^n -1
fn compute_vanishing_poly_over_coset(
    domain: &EvaluationDomain, // domain to evaluate over
    poly_degree: u64,          // degree of the vanishing polynomial
) -> Vec<Scalar> {
    use crate::fft::constants::GENERATOR;
    let multiplicative_gen = GENERATOR;

    let coset_gen = multiplicative_gen.pow(&[poly_degree, 0, 0, 0]);
    let v_h: Vec<_> = (0..domain.size())
        .into_iter()
        .map(|i| {
            (coset_gen * &domain.group_gen.pow(&[poly_degree * i as u64, 0, 0, 0])) - &Scalar::one()
        })
        .collect();
    v_h
}

#[cfg(test)]
mod test {
    use super::*;
    use bls12_381::Scalar as Fr;
    #[test]
    fn test_l1_x_poly() {
        let n = 4;
        let domain = EvaluationDomain::new(n).unwrap();

        let rand_point = Fr::from_raw([1, 2, 3, 4]);
        assert_ne!(rand_point, Fr::zero());

        // Compute l1_eval according to the Domain
        let l1_a = domain.evaluate_all_lagrange_coefficients(rand_point)[0];
        // Compute l1 eval using IFFT
        let b = compute_first_lagrange_poly(&domain);
        let l1_b = b.evaluate(&rand_point);

        assert_eq!(l1_a, l1_b);

        assert_eq!(b.evaluate(&Fr::one()), Fr::one());
    }
}
