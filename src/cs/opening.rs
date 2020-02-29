use super::linearisation::LinEval;
use crate::cs::poly_utils::Poly_utils;
use crate::fft::Polynomial;
use bls12_381::Scalar;
use itertools::izip;
use rayon::prelude::*;
pub struct commitmentOpener {}
impl commitmentOpener {
    pub fn new() -> Self {
        commitmentOpener {}
    }

    pub fn compute_opening_polynomials(
        &self,
        root_of_unity: Scalar,
        n: usize,
        z_challenge: Scalar,
        lin_coeffs: &Vec<Scalar>,
        evaluations: LinEval,
        t_lo_coeffs: &Vec<Scalar>,
        t_mid_coeffs: &Vec<Scalar>,
        t_hi_coeffs: &Vec<Scalar>,
        w_l_coeffs: &Vec<Scalar>,
        w_r_coeffs: &Vec<Scalar>,
        w_o_coeffs: &Vec<Scalar>,
        sigma_1_coeffs: &Vec<Scalar>,
        sigma_2_coeffs: &Vec<Scalar>,
        z_coeffs: &Vec<Scalar>,
        v: &Scalar,
    ) -> (Vec<Scalar>, Vec<Scalar>) {
        let poly_utils: Poly_utils = Poly_utils::new();

        // Compute 1,v, v^2, v^3,..v^7
        let mut v_pow: Vec<Scalar> = poly_utils.powers_of(v, 7);

        let v_7 = v_pow.pop().unwrap();
        let z_hat_eval = evaluations.perm_eval;

        // Compute z^n , z^2n
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);

        let quotient_coeffs = self.compute_quotient_opening_poly(
            &t_lo_coeffs,
            &t_mid_coeffs,
            &t_hi_coeffs,
            z_n,
            z_two_n,
        );
        let polynomials = vec![
            &quotient_coeffs,
            lin_coeffs,
            w_l_coeffs,
            w_r_coeffs,
            w_o_coeffs,
            sigma_1_coeffs,
            sigma_2_coeffs,
        ];

        // Compute opening polynomial
        let k = self.compute_challenge_poly_eval(v_pow, polynomials, evaluations);

        // Compute W_z(X)
        let W_z = self.compute_witness_polynomial(&k, z_challenge);

        // Compute shifted polynomial
        let shifted_z = z_challenge * &root_of_unity;

        let mut W_zw = self.compute_witness_polynomial(z_coeffs, shifted_z);
        W_zw = &W_zw * &Polynomial::from_coefficients_vec(vec![v_7]);

        (W_z.coeffs, W_zw.coeffs)
    }

    fn compute_quotient_opening_poly(
        &self,
        t_lo_coeffs: &[Scalar],
        t_mid_coeffs: &[Scalar],
        t_hi_coeffs: &[Scalar],
        z_n: Scalar,
        z_two_n: Scalar,
    ) -> Vec<Scalar> {
        let poly_utils: Poly_utils = Poly_utils::new();

        let a = t_lo_coeffs;
        let b: Vec<_> = t_mid_coeffs.par_iter().map(|mid| z_n * mid).collect();
        let c: Vec<_> = t_hi_coeffs.par_iter().map(|hi| z_two_n * hi).collect();

        let ab = poly_utils.add_poly_vectors(&a, &b);
        let res = poly_utils.add_poly_vectors(&ab, &c);

        res
    }

    // computes sum [ challenge[i] * (polynomials[i] - evaluations[i])]
    fn compute_challenge_poly_eval(
        &self,
        challenges: Vec<Scalar>,
        polynomials: Vec<&Vec<Scalar>>,
        evaluations: LinEval,
    ) -> Vec<Scalar> {
        let poly_utils: Poly_utils = Poly_utils::new();
        let x: Vec<_> = challenges
            .into_par_iter()
            .zip(polynomials.into_par_iter())
            .zip(evaluations.to_vec().into_par_iter())
            .map(|((v, poly), eval)| {
                let mut p: Vec<_> = poly.iter().map(|p| v * p).collect();
                p[0] = p[0] - &(v * &eval);
                p
            })
            .collect();

        let mut sum = Vec::new();
        for poly in x.iter() {
            sum = poly_utils.add_poly_vectors(&poly, &sum);
        }

        sum
    }

    // Given P(X) and `z`. compute P(X) - P(z) / X - z
    fn compute_witness_polynomial(&self, p_coeffs: &Vec<Scalar>, z: Scalar) -> Polynomial {
        let p = &Polynomial::from_coefficients_slice(p_coeffs);
        // evaluate polynomial at z
        let p_eval = p.evaluate(z);
        // convert value to a polynomial
        let poly_eval = Polynomial::from_coefficients_vec(vec![p_eval]);

        // Construct divisor for kate witness
        let divisor = Polynomial::from_coefficients_vec(vec![-z, Scalar::one()]);

        // Compute witness polynomial
        let witness_polynomial = &(p - &poly_eval) / &divisor;

        witness_polynomial
    }
}
