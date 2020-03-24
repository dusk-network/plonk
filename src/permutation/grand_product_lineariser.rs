use crate::fft::{EvaluationDomain, Polynomial};
use crate::permutation::constants::{K1, K2, K3};
use bls12_381::Scalar;
/// See Linearisation technique from Mary Maller for details
// XXX: We need better names for these functions
/// Computes the semi evaluted Identity permutation polynomial component of the grand product
pub fn compute_identity_polynomial(
    a_eval: &Scalar,
    b_eval: &Scalar,
    c_eval: &Scalar,
    d_eval: &Scalar,
    z_challenge: &Scalar,
    alpha: &Scalar,
    beta: &Scalar,
    gamma: &Scalar,
    z_poly: &Polynomial,
) -> Polynomial {
    let beta_z = beta * z_challenge;

    // a_eval + beta * z_challenge + gamma
    let mut a_0 = a_eval + beta_z;
    a_0 += gamma;

    // b_eval + beta * K1 * z_challenge + gamma
    let beta_z_K1 = K1 * beta_z;
    let mut a_1 = b_eval + beta_z_K1;
    a_1 += gamma;

    // c_eval + beta * K2 * z_challenge + gamma
    let beta_z_K2 = K2 * beta_z;
    let mut a_2 = c_eval + beta_z_K2;
    a_2 += gamma;

    // d_eval + beta * K3 * z_challenge + gamma
    let beta_z_K3 = K3 * beta_z;
    let mut a_3 = d_eval + beta_z_K3;
    a_3 += gamma;

    let mut a = a_0 * a_1;
    a = a * a_2;
    a = a * a_3;
    a = a * alpha; // (a_eval + beta * z_challenge + gamma)(b_eval + beta * K1 * z_challenge + gamma)(c_eval + beta * K2 * z_challenge + gamma)(d_eval + beta * K3 * z_challenge + gamma) * alpha

    z_poly * &a // (a_eval + beta * z_challenge + gamma)(b_eval + beta * K1 * z_challenge + gamma)(c_eval + beta * K2 * z_challenge + gamma) * alpha z(X)
}

/// Computes the semi-evaluated Copy permutation polynomial component of the grand product
pub fn compute_copy_polynomial(
    (a_eval, b_eval, c_eval): &(Scalar, Scalar, Scalar),
    z_eval: &Scalar,
    sigma_1_eval: &Scalar,
    sigma_2_eval: &Scalar,
    sigma_3_eval: &Scalar,
    (alpha, beta, gamma): &(Scalar, Scalar, Scalar),
    fourth_sigma_poly: &Polynomial,
) -> Polynomial {
    // a_eval + beta * sigma_1 + gamma
    let beta_sigma_1 = beta * sigma_1_eval;
    let mut a_0 = a_eval + beta_sigma_1;
    a_0 += gamma;

    // b_eval + beta * sigma_2 + gamma
    let beta_sigma_2 = beta * sigma_2_eval;
    let mut a_1 = b_eval + beta_sigma_2;
    a_1 += gamma;

    // c_eval + beta * sigma_3 + gamma
    let beta_sigma_3 = beta * sigma_3_eval;
    let mut a_2 = c_eval + beta_sigma_3;
    a_2 += gamma;

    let beta_z_eval = beta * z_eval;

    let mut a = a_0 * a_1 * a_2;
    a = a * beta_z_eval;
    a = a * alpha; // (a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma)(c_eval + beta * sigma_3 + gamma) * beta *z_eval * alpha

    fourth_sigma_poly * &-a // -(a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma) (c_eval + beta * sigma_3 + gamma) * beta *z_eval * alpha^2 * Sigma_4(X)
}
/// Computes the semi-evaluated check that the first L_1(w^1) = 1
pub fn compute_is_one_polynomial(
    domain: &EvaluationDomain,
    z_challenge: &Scalar,
    alpha_sq: &Scalar,
    z_coeffs: &Polynomial,
) -> Polynomial {
    // Evaluate l_1(z)
    let l_1_z = domain.evaluate_all_lagrange_coefficients(*z_challenge)[0];

    z_coeffs * &(l_1_z * alpha_sq)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fft::Polynomial;
    use bls12_381::Scalar as Fr;

    #[test]
    fn test_second_component() {
        let alpha = Fr::one();
        let beta = Fr::one();
        let gamma = Fr::one();

        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let c_eval = Fr::one();
        let d_eval = Fr::one();
        let z_challenge = Fr::one();

        let z_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = compute_identity_polynomial(
            &a_eval,
            &b_eval,
            &c_eval,
            &d_eval,
            &z_challenge,
            &alpha,
            &beta,
            &gamma,
            &z_poly,
        );

        let first_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3)]);
        let second_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(2) + &K1]);
        let third_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(2) + &K2]);
        let fourth_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(2) + &K3]);

        let mut expected_poly = &first_bracket * &second_bracket;
        expected_poly = &expected_poly * &third_bracket;
        expected_poly = &expected_poly * &fourth_bracket;
        expected_poly = &expected_poly * &z_poly;

        assert_eq!(got_poly, expected_poly);
    }
    #[test]
    fn test_third_component() {
        let alpha = Fr::one();
        let beta = Fr::one();
        let gamma = Fr::one();

        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let c_eval = Fr::one();
        let sig1_eval = Fr::one();
        let sig2_eval = Fr::one();
        let sig3_eval = Fr::one();
        let z_eval = Fr::one();

        let sig4_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = compute_copy_polynomial(
            &(a_eval, b_eval, c_eval),
            &z_eval,
            &sig1_eval,
            &sig2_eval,
            &sig3_eval,
            &(alpha, beta, gamma),
            &sig4_poly,
        );

        let first_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3)]);
        let second_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3)]);
        let third_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3)]);
        let fourth_bracket = Polynomial::from_coefficients_vec(vec![z_eval]);

        let mut expected_poly = &first_bracket * &second_bracket;
        expected_poly = &expected_poly * &third_bracket;
        expected_poly = &expected_poly * &fourth_bracket;
        expected_poly = &expected_poly * &sig4_poly;

        assert_eq!(got_poly, -expected_poly);
    }
    #[test]
    fn test_fourth_component() {
        let alpha = Fr::one();
        let z_challenge = Scalar::from(123);
        let domain = EvaluationDomain::new(10).unwrap();
        let z_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = compute_is_one_polynomial(&domain, &z_challenge, &alpha, &z_poly);

        let l1_eval = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];
        let l1_eval_poly = Polynomial::from_coefficients_vec(vec![l1_eval]);

        let expected_poly = &z_poly * &l1_eval_poly;

        assert_eq!(got_poly, expected_poly);
    }
}
