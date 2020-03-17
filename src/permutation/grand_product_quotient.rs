use crate::fft::Evaluations;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::permutation::constants::{K1, K2, K3};
use bls12_381::Scalar;
use rayon::prelude::*;
/// Computes the Identity permutation polynomial component of the grand product
pub fn compute_identity_polynomial(
    domain: &EvaluationDomain,
    alpha_sq: &Scalar,
    beta: &Scalar,
    gamma: &Scalar,
    z_eval_4n: &Vec<Scalar>,
    wl_coeffs: &Polynomial,
    wr_coeffs: &Polynomial,
    wo_coeffs: &Polynomial,
    w4_coeffs: &Polynomial,
) -> Evaluations {
    let n = domain.size();
    let domain_4n = EvaluationDomain::new(4 * n).unwrap();

    // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)(d(X) + beta * k3 * X + gamma)
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

    let mut d = w4_coeffs.to_vec();
    d[0] = d[0] + gamma;
    let beta_k3 = *beta * K3;
    d[1] = d[1] + &beta_k3;

    domain_4n.coset_fft_in_place(&mut a);
    domain_4n.coset_fft_in_place(&mut b);
    domain_4n.coset_fft_in_place(&mut c);
    domain_4n.coset_fft_in_place(&mut d);

    let t_2: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let z = &z_eval_4n[i];

            let mut product = a[i] * &b[i] * &c[i] * &d[i]; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)(d(X) + beta * k3 * X + gamma)
            product = product * z; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)(d(X) + beta * k3 * X + gamma)z(X) * alpha^2

            product * alpha_sq
        })
        .collect();
    Evaluations::from_vec_and_domain(t_2, domain_4n)
}
/// Computes the Copy permutation polynomial component of the grand product
pub fn compute_copy_polynomial(
    domain: &EvaluationDomain,
    alpha_sq: &Scalar,
    beta: &Scalar,
    gamma: &Scalar,
    z_eval_4n: &Vec<Scalar>,
    wl_poly: &Polynomial,
    wr_poly: &Polynomial,
    wo_poly: &Polynomial,
    w4_poly: &Polynomial,
    left_sigma_poly: &Polynomial,
    right_sigma_poly: &Polynomial,
    out_sigma_poly: &Polynomial,
    fourth_sigma_poly: &Polynomial,
) -> Evaluations {
    let n = domain.size();
    let domain_4n = EvaluationDomain::new(4 * n).unwrap();

    // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)(d(X) + beta * Sigma4(X) + gamma)
    //
    let beta_left_sigma = left_sigma_poly * beta;
    let beta_right_sigma = right_sigma_poly * beta;
    let beta_out_sigma = out_sigma_poly * beta;
    let beta_fourth_sigma = fourth_sigma_poly * beta;
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
    //(d(X) + beta * Sigma4(X) + gamma)
    //
    let mut d = &beta_fourth_sigma + w4_poly;
    d[0] = d[0] + gamma;

    let a_fft = domain_4n.coset_fft(&a);
    let b_fft = domain_4n.coset_fft(&b);
    let c_fft = domain_4n.coset_fft(&c);
    let d_fft = domain_4n.coset_fft(&d);

    let t_3: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| {
            let z_shifted = &z_eval_4n[i + 4];

            let mut product = a_fft[i] * b_fft[i] * c_fft[i] * d_fft[i]; // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)(d(X) + beta * Sigma4(X) + gamma)
            product = product * z_shifted;

            -product * alpha_sq // (a(x) + beta* Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)(d(X) + beta * Sigma4(X) + gamma) Z(X.omega) * alpha^2
        })
        .collect();

    Evaluations::from_vec_and_domain(t_3, domain_4n)
}
/// Ensures that the polynomial evaluated at the first root of unity is one
pub fn compute_is_one_polynomial(
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
    z_coeffs[0] = z_coeffs[0] - Scalar::one();

    let z_evals = domain_4n.coset_fft(&z_coeffs);
    let alpha_cu_l1_evals = domain_4n.coset_fft(&alpha_cu_l1_poly.coeffs);

    let t_4: Vec<_> = (0..domain_4n.size())
        .into_par_iter()
        .map(|i| alpha_cu_l1_evals[i] * z_evals[i])
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
