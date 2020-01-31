use crate::cs::poly_utils::Poly_utils;
use crate::transcript::TranscriptProtocol;
use algebra::{curves::PairingEngine, fields::Field};
use ff_fft::DensePolynomial as Polynomial;
use itertools::izip;
use rayon::prelude::*;
use std::marker::PhantomData;
pub struct commitmentOpener<E: PairingEngine> {
    _engine: PhantomData<E>,
}
impl<E: PairingEngine> commitmentOpener<E> {
    pub fn new() -> Self {
        commitmentOpener {
            _engine: PhantomData,
        }
    }

    pub fn compute_opening_polynomials(
        &self,
        root_of_unity: E::Fr,
        n: usize,
        z_challenge: E::Fr,
        lin_coeffs: &Vec<E::Fr>,
        evaluations: &Vec<E::Fr>,
        t_lo_coeffs: &Vec<E::Fr>,
        t_mid_coeffs: &Vec<E::Fr>,
        t_hi_coeffs: &Vec<E::Fr>,
        w_l_coeffs: &Vec<E::Fr>,
        w_r_coeffs: &Vec<E::Fr>,
        w_o_coeffs: &Vec<E::Fr>,
        sigma_1_coeffs: &Vec<E::Fr>,
        sigma_2_coeffs: &Vec<E::Fr>,
        z_poly: &Polynomial<E::Fr>,
        v: &E::Fr,
    ) -> (Vec<E::Fr>, Vec<E::Fr>) {
        let mut evaluations = evaluations.to_vec();
        let poly_utils: Poly_utils<E> = Poly_utils::new();

        // Compute 1,v, v^2, v^3,..v^7
        let mut v_pow: Vec<E::Fr> = poly_utils.powers_of(v, 7);

        let v_7 = v_pow.pop().unwrap();
        let z_eval = evaluations.pop().unwrap(); // XXX: For better readability, we should probably have an evaluation struct. It is a vector so that we can iterate in compute_challenge_poly_eval

        // Compute z^n , z^2n
        let z_n = z_challenge.pow(&[n as u64]);
        let z_two_n = z_challenge.pow(&[2 * n as u64]);

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

        let mut W_zw = self.compute_witness_polynomial(z_poly, shifted_z);
        W_zw = &W_zw * &Polynomial::from_coefficients_vec(vec![v_7]);

        (W_z.coeffs, W_zw.coeffs)
    }

    fn compute_quotient_opening_poly(
        &self,
        t_lo_coeffs: &[E::Fr],
        t_mid_coeffs: &[E::Fr],
        t_hi_coeffs: &[E::Fr],
        z_n: E::Fr,
        z_two_n: E::Fr,
    ) -> Vec<E::Fr> {
        let poly_utils: Poly_utils<E> = Poly_utils::new();

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
        challenges: Vec<E::Fr>,
        polynomials: Vec<&Vec<E::Fr>>,
        evaluations: Vec<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let poly_utils: Poly_utils<E> = Poly_utils::new();
        let x: Vec<_> = challenges
            .into_par_iter()
            .zip(polynomials.into_par_iter())
            .zip(evaluations.into_par_iter())
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

        Polynomial::from_coefficients_vec(sum)
    }

    // Given P(X) and `z`. compute P(X) - P(z) / X - z
    fn compute_witness_polynomial(&self, p: &Polynomial<E::Fr>, z: E::Fr) -> Polynomial<E::Fr> {
        // evaluate polynomial at z
        let p_eval = p.evaluate(z);
        // convert value to a polynomial
        let poly_eval = Polynomial::from_coefficients_vec(vec![p_eval]);

        // Construct divisor for kate witness
        let divisor = Polynomial::from_coefficients_vec(vec![-z, E::Fr::one()]);

        // Compute witness polynomial
        let witness_polynomial = &(p - &poly_eval) / &divisor;

        witness_polynomial
    }
}
