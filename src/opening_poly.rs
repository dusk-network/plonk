use crate::constraint_system::standard::linearisation_poly::Evaluations;
use crate::fft::Polynomial;
use crate::util::powers_of;
use bls12_381::Scalar;
use itertools::izip;
use rayon::prelude::*;

pub fn compute(
    root_of_unity: Scalar,
    n: usize,
    z_challenge: Scalar,
    lin_poly: &Polynomial,
    evaluations: &Evaluations,
    t_lo_poly: &Polynomial,
    t_mid_poly: &Polynomial,
    t_hi_poly: &Polynomial,
    w_l_poly: &Polynomial,
    w_r_poly: &Polynomial,
    w_o_poly: &Polynomial,
    sigma_1_poly: &Polynomial,
    sigma_2_poly: &Polynomial,
    z_poly: &Polynomial,
    v: &Scalar,
) -> (Polynomial, Polynomial) {
    // Compute 1,v, v^2, v^3,..v^7
    let mut v_pow: Vec<Scalar> = powers_of(v, 7);

    let v_7 = v_pow.pop().unwrap();
    let z_hat_eval = evaluations.proof.perm_eval;

    // Compute z^n , z^2n
    let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
    let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);

    let quotient_poly =
        compute_quotient_opening_poly(&t_lo_poly, &t_mid_poly, &t_hi_poly, z_n, z_two_n);
    let polynomials = vec![
        &quotient_poly,
        lin_poly,
        w_l_poly,
        w_r_poly,
        w_o_poly,
        sigma_1_poly,
        sigma_2_poly,
    ];

    // Compute opening polynomial
    let k = compute_challenge_poly_eval(v_pow, polynomials, evaluations);

    // Compute W_z(X)
    let W_z = compute_witness_polynomial(&k, z_challenge);

    // Compute shifted polynomial
    let shifted_z = z_challenge * &root_of_unity;

    let mut W_zw = compute_witness_polynomial(z_poly, shifted_z);
    W_zw = &W_zw * &Polynomial::from_coefficients_vec(vec![v_7]);

    (W_z, W_zw)
}

fn compute_quotient_opening_poly(
    t_lo_poly: &Polynomial,
    t_mid_poly: &Polynomial,
    t_hi_poly: &Polynomial,
    z_n: Scalar,
    z_two_n: Scalar,
) -> Polynomial {
    let a = t_lo_poly;
    let b = t_mid_poly * &z_n;
    let c = t_hi_poly * &z_two_n;

    let ab = a + &b;
    let res = &ab + &c;

    res
}

// Computes sum [ challenge[i] * (polynomials[i] - evaluations[i])]
fn compute_challenge_poly_eval(
    challenges: Vec<Scalar>,
    polynomials: Vec<&Polynomial>,
    evaluations: &Evaluations,
) -> Polynomial {
    let x = challenges
        .into_par_iter()
        .zip(polynomials.into_par_iter())
        .zip(evaluations.as_vec().into_par_iter())
        .map(|((v, poly), eval)| {
            let poly_minus_eval = poly - eval;
            &poly_minus_eval * &v
        })
        .sum();

    x
}

// Given P(X) and `z`. compute P(X) - P(z) / X - z
fn compute_witness_polynomial(p_poly: &Polynomial, z: Scalar) -> Polynomial {
    // evaluate polynomial at z
    let p_eval = p_poly.evaluate(&z);
    // convert value to a polynomial
    let poly_eval = Polynomial::from_coefficients_vec(vec![p_eval]);

    // Construct divisor for kate witness
    let divisor = Polynomial::from_coefficients_vec(vec![-z, Scalar::one()]);

    // Compute witness polynomial
    let witness_polynomial = &(p_poly - &poly_eval) / &divisor;

    witness_polynomial
}
