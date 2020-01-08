use crate::cs::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use std::marker::PhantomData;

pub struct QuotientToolkit<E: PairingEngine> {
    _engine: PhantomData<E>,
}
impl<E: PairingEngine> QuotientToolkit<E> {
    pub fn new() -> Self {
        QuotientToolkit {
            _engine: PhantomData,
        }
    }

    #[allow(dead_code)]
    pub fn compute_quotient_poly(
        &self,
        n: usize,
        domain: &EvaluationDomain<E::Fr>,
        prep_circ: &PreProcessedCircuit<E>,
        w_poly: [&Polynomial<E::Fr>; 3],
        pi_poly: &Polynomial<E::Fr>,
        (gamma, beta, alpha): &(E::Fr, E::Fr, E::Fr),
        z_poly: &Polynomial<E::Fr>,
    ) -> (
        Polynomial<E::Fr>,
        Polynomial<E::Fr>,
        Polynomial<E::Fr>,
        E::Fr,
    ) {
        // Compute `alpha` polynomial (degree zero).
        let alpha_poly = Polynomial::from_coefficients_slice(&[*alpha]);
        // Compute `gamma` polynomial (degree zero).
        let gamma_poly = Polynomial::from_coefficients_slice(&[*gamma]);

        // Get wire polynomials by its names to clarify the rest of the code.
        let w_l_poly = w_poly[0];
        let w_r_poly = w_poly[1];
        let w_o_poly = w_poly[2];
        // Rename wire-selector polynomials to clarify code.
        let qm_ws_poly = &prep_circ.qm_poly();
        let ql_ws_poly = &prep_circ.ql_poly();
        let qr_ws_poly = &prep_circ.qr_poly();
        let qo_ws_poly = &prep_circ.qo_poly();
        let qc_ws_poly = &prep_circ.qc_poly();

        // t0 represents the first polynomial that forms `t(X)`.
        let t0 = {
            let t00 = &(w_l_poly * w_r_poly) * qm_ws_poly;
            let t01 = w_l_poly * ql_ws_poly;
            let t02 = w_r_poly * qr_ws_poly;
            let t03 = w_o_poly * qo_ws_poly;
            let t04 = pi_poly + qc_ws_poly;
            // Compute `alpha/Zh(X)`
            let (t05, _) = alpha_poly.divide_by_vanishing_poly(*domain).unwrap();

            &(&(&(&(&t00 + &t01) + &t02) + &t03) + &t04) * &t05
        };

        // t1 represents the second polynomial that forms `t(X)`.
        let t1 = {
            // beta*X poly
            let beta_x_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), *beta]);
            let t10 = w_l_poly + &(&beta_x_poly + &gamma_poly);
            // Beta*k1
            let beta_k1: E::Fr = *beta * &E::Fr::multiplicative_generator();
            // Beta*k1 poly
            let beta_k1_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), beta_k1]);
            let t11 = &(w_r_poly + &beta_k1_poly) + &gamma_poly;
            // Beta*k2
            let beta_k2: E::Fr = *beta * &E::Fr::from(13);
            // Beta*k2 poly
            let beta_k2_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), beta_k2]);
            let t12 = &(w_o_poly + &beta_k2_poly) + &gamma_poly;
            // Compute `alpha^2/Zh(X)`
            let (t14, _) = Polynomial::from_coefficients_slice(&[alpha.square()])
                .divide_by_vanishing_poly(*domain)
                .unwrap();
            &(&(&(&t10 * &t11) * &t12) * &z_poly) * &t14
        };

        // t2 represents the third polynomial that forms `t(X)`.
        let t2 = {
            // Beta poly (Degree 0).
            let beta_poly = Polynomial::from_coefficients_slice(&[*beta]);
            // Compute Sigma polys.
            let sigma_1_beta_poly =
                &Polynomial::from_coefficients_slice(prep_circ.left_sigma_poly()) * &beta_poly;
            let sigma_2_beta_poly =
                &Polynomial::from_coefficients_slice(prep_circ.right_sigma_poly()) * &beta_poly;
            let sigma_3_beta_poly =
                &Polynomial::from_coefficients_slice(prep_circ.out_sigma_poly()) * &beta_poly;

            let t20 = &(w_l_poly + &sigma_1_beta_poly) + &gamma_poly;
            let t21 = &(w_r_poly + &sigma_2_beta_poly) + &gamma_poly;
            let t22 = &(w_o_poly + &sigma_3_beta_poly) + &gamma_poly;

            // FFT t20-23 with 4n domain. Then transpolate z(X), multiply them and ifft.
            // Then multiply by vanishing poly.
            let t_0_3_mul = self.mul_and_transp_in_4n(n, &[t20, t21, t22], z_poly);

            // Compute `alpha^2/Zh(X)`
            let (t24, _) = Polynomial::from_coefficients_slice(&[alpha.square()])
                .divide_by_vanishing_poly(*domain)
                .unwrap();
            &t_0_3_mul * &t24
        };

        // t3 represents the fourth polynomial that forms `t(X)`.
        let t3 = {
            // Build `1` poly (degree 0).
            let one_poly = Polynomial::from_coefficients_slice(&[E::Fr::from(1)]);
            let t30 = z_poly - &one_poly;
            // Compute `alpha^3/Zh(X)`
            let (t31, _) = Polynomial::from_coefficients_slice(&[alpha.square() * &alpha])
                .divide_by_vanishing_poly(*domain)
                .unwrap();
            // Get L1(x) and compute the result.
            &(&t30 * &t31) * &self.compute_lagrange_poly_evaluation(n as u8)
        };

        let t_x = &(&(&t0 + &t1) - &t2) + &t3;
        // Split `t(X)`

        // Build 0+ X + X^n + X^2n poly.
        let x_pow_2n = {
            let mut vec = Vec::new();
            for _ in 0..(n * 2) {
                vec.push(E::Fr::zero());
            }
            vec.push(E::Fr::from(1));
            vec
        };
        let x_pow_2n_poly = Polynomial::from_coefficients_slice(&x_pow_2n);
        let x_pow_n_poly = Polynomial::from_coefficients_slice(&x_pow_2n[0..=n]);
        let t_x_split = self.split_tx_poly(n, &t_x);
        // Build t_low(X)
        let t_lo = t_x_split[0].clone();
        // Build t_mid(X)
        let t_mid = &x_pow_n_poly * &t_x_split[1];
        // Build t_hi(X)
        let t_hi = &x_pow_2n_poly * &t_x_split[2];
        (t_lo, t_mid, t_hi, *alpha)
    }

    /// Computes the Lagrange polynomial evaluation `L1(z)`.
    pub fn compute_lagrange_poly_evaluation(&self, n: u8) -> Polynomial<E::Fr> {
        // One as a polynomial of degree 0.
        let one_poly = Polynomial::from_coefficients_slice(&[E::Fr::from(1)]);
        // Build z_nth vector to get the poly directly in coef form.
        let mut z_nth = Vec::new();
        for _ in 0..n {
            z_nth.push(E::Fr::zero());
        }
        // Add 1 on the n'th term of the vec.
        z_nth.push(E::Fr::from(1));
        // Build the poly.
        let z_nth_poly = Polynomial::from_coefficients_vec(z_nth);
        // `n` as polynomial of degree 0.
        let n_poly = Polynomial::from_coefficients_slice(&[E::Fr::from(n as u8)]);
        let z_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), E::Fr::from(1)]);

        &(&z_nth_poly - &one_poly) / &(&n_poly * &(&z_poly - &one_poly))
    }

    // Gets a set of polynomials, passes them to coeficient form
    // with EvalDomain = 4*n. Then multiplies them by `z(Xw)` and
    // returns the ifft of the mul over the domain `4n` again.
    pub fn mul_and_transp_in_4n(
        &self,
        n: usize,
        t2s_polys: &[Polynomial<E::Fr>; 3],
        z_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let ev_dom_4n = EvaluationDomain::new(4 * n).unwrap();
        let polys_4n: Vec<Polynomial<E::Fr>> = t2s_polys
            .into_iter()
            .map(|p| {
                let pol = { Polynomial::from_coefficients_slice(&ev_dom_4n.fft(p)) };
                pol
            })
            .collect();

        let z_eval_coef = self.transpolate_poly_to_unity_root(n, &z_poly);

        let total_poly: Polynomial<E::Fr> = {
            let mut tot: Polynomial<E::Fr> = Polynomial::zero();
            for poly in polys_4n {
                tot = &tot * &poly;
            }
            tot = &tot * &z_eval_coef;
            tot
        };

        Polynomial::from_coefficients_slice(&ev_dom_4n.ifft(&total_poly))
    }

    // Moves the polynomial on the complex plane in respect to the
    // first root of unity and returns the poly in coeficient form.
    pub fn transpolate_poly_to_unity_root(
        &self,
        n: usize,
        poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let domain_4n = EvaluationDomain::new(4 * n).unwrap();
        let mut poly_coef = domain_4n.fft(poly);
        poly_coef.push(poly_coef[0]);
        poly_coef.push(poly_coef[1]);
        poly_coef.push(poly_coef[2]);
        poly_coef.push(poly_coef[3]);
        let mut coefs_rotated: Vec<E::Fr> = Vec::with_capacity(poly_coef.len());
        coefs_rotated.clone_from_slice(&poly_coef[4..]);
        Polynomial::from_coefficients_vec(coefs_rotated)
    }

    // Split `t(X)` poly into three degree-n polynomials.
    pub fn split_tx_poly(&self, n: usize, t_x: &Polynomial<E::Fr>) -> [Polynomial<E::Fr>; 3] {
        [
            Polynomial::from_coefficients_slice(&t_x[0..n]),
            Polynomial::from_coefficients_slice(&t_x[n..2 * n]),
            Polynomial::from_coefficients_slice(&t_x[2 * n..]),
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381 as E;
    use algebra::fields::bls12_381::Fr;

    #[test]
    fn test_split_poly() {
        let n = 4;

        // Compute random point
        use algebra::UniformRand;
        let rand_point = Fr::rand(&mut rand::thread_rng());
        let rand_point_n = rand_point.pow(&[n as u64]);
        let rand_point_2n = rand_point.pow(&[2 * n as u64]);

        // Generate a random quotient polynomial
        let t_x = Polynomial::rand(3 * n, &mut rand::thread_rng());
        let t_x_eval = t_x.evaluate(rand_point);

        // Split t(x) into 3 n-degree polynomials
        let toolkit: QuotientToolkit<E> = QuotientToolkit::new();
        let t_components = toolkit.split_tx_poly(n, &t_x);

        // Evaluate n-degree polynomials
        let t_lo_eval = t_components[0].evaluate(rand_point);

        let mut t_mid_eval = t_components[1].evaluate(rand_point);
        t_mid_eval = t_mid_eval * &rand_point_n;

        let mut t_hi_eval = t_components[2].evaluate(rand_point);
        t_hi_eval = t_hi_eval * &rand_point_2n;

        let mut t_components_eval = t_lo_eval + &t_mid_eval;
        t_components_eval += &t_hi_eval;

        assert_eq!(t_x_eval, t_components_eval);
    }
}
