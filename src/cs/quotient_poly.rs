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
        domain: &EvaluationDomain<E::Fr>,
        prep_circ: &PreProcessedCircuit<E>,
        w_poly: [&Polynomial<E::Fr>; 3],
        pi_poly: &Polynomial<E::Fr>,
        (gamma, beta, alpha): &(E::Fr, E::Fr, E::Fr),
        z_poly: &Polynomial<E::Fr>,
    ) -> (Polynomial<E::Fr>, Polynomial<E::Fr>, Polynomial<E::Fr>) {
        // Compute `alpha` polynomial (degree zero).
        let alpha_poly = Polynomial::from_coefficients_slice(&[*alpha]);
        // Compute `gamma` polynomial (degree zero).
        let gamma_poly = Polynomial::from_coefficients_slice(&[*gamma]);

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
        (t_lo, t_mid, t_hi)
    }

    fn compute_quotient_first_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        q_m_poly: &Polynomial<E::Fr>,
        q_l_poly: &Polynomial<E::Fr>,
        q_r_poly: &Polynomial<E::Fr>,
        q_o_poly: &Polynomial<E::Fr>,
        q_c_poly: &Polynomial<E::Fr>,
        alpha_poly: Polynomial<E::Fr>,
        w_l_poly: &Polynomial<E::Fr>,
        w_r_poly: &Polynomial<E::Fr>,
        w_o_poly: &Polynomial<E::Fr>,
        public_input_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let n = domain.size();

        // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + PI(X) + Q_C(X))
        //
        //(a(x)b(x)q_M(x)
        let mut a_1 = w_l_poly * w_r_poly;
        a_1 = &a_1 * q_m_poly;
        //
        //a(x)q_L(x)
        let a_2 = w_l_poly * q_l_poly;
        //
        //b(X)q_R(x)
        let a_3 = w_r_poly * q_r_poly;
        //
        //c(X)q_O(X)
        let a_4 = w_o_poly * q_o_poly;
        //
        // PI(x) + Q_C(X)
        let a_5 = public_input_poly + q_c_poly;

        let mut a = &a_1 + &a_2; // (a(x)b(x)q_M(x) + a(x)q_L(x)
        a += &a_3; // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x)
        a += &a_4; // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X)
        a += &a_5; // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + PI(X) + Q_C(X))

        a = &a * &alpha_poly; // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + PI(X) + Q_C(X)) * alpha
        let (q, _) = a.divide_by_vanishing_poly(*domain).unwrap(); // ((a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + PI(X) + Q_C(X)) * alpha) / Z_H

        assert_eq!(q.degree(), 2 * n + 1);

        q
    }

    fn compute_quotient_second_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        alpha_sq_poly: &Polynomial<E::Fr>,
        k1: &E::Fr,
        k2: &E::Fr,
        beta: &E::Fr,
        z_poly: &Polynomial<E::Fr>,
        w_l_gamma_poly: &Polynomial<E::Fr>,
        w_r_gamma_poly: &Polynomial<E::Fr>,
        w_o_gamma_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let beta = *beta;
        let n = domain.size();

        // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)
        //
        //(a(x) + beta * X + gamma)
        let beta_X = Polynomial::from_coefficients_vec(vec![E::Fr::zero(), beta]);
        let a_1 = w_l_gamma_poly + &beta_X;
        // assert_eq!(self.n, a_1.degree());
        //
        //(b(X) + beta * k1 * X + gamma)
        let beta_k1_X = Polynomial::from_coefficients_vec(vec![E::Fr::zero(), beta * k1]);
        let a_2 = w_r_gamma_poly + &beta_k1_X;
        //
        //(c(X) + beta * k2 * X + gamma)
        let beta_k2_X = Polynomial::from_coefficients_vec(vec![E::Fr::zero(), beta * k2]);
        let a_3 = w_o_gamma_poly + &beta_k2_X;

        let mut a = &a_1 * &a_2; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma)
        a = &a * &a_3; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)
        a = &a * z_poly; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)z(X)
        a = &a * alpha_sq_poly; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)z(X) * alpha^2
        let (q, _) = a.divide_by_vanishing_poly(*domain).unwrap(); // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)z(X) * alpha^2 / Z_H

        assert_eq!(q.degree(), 3 * n + 5);

        q
    }

    fn compute_quotient_third_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        alpha_sq_poly: &Polynomial<E::Fr>,
        beta: &E::Fr,
        shifted_z_poly: &Polynomial<E::Fr>,
        w_l_gamma_poly: &Polynomial<E::Fr>,
        w_r_gamma_poly: &Polynomial<E::Fr>,
        w_o_gamma_poly: &Polynomial<E::Fr>,
        left_sigma_poly: &Polynomial<E::Fr>,
        right_sigma_poly: &Polynomial<E::Fr>,
        out_sigma_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let beta = *beta;
        let n = domain.size();
        // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)
        //
        let poly_beta = Polynomial::from_coefficients_vec(vec![beta]);
        //
        // (a(x) + beta * Sigma1(X) + gamma)
        let beta_left_sigma = &poly_beta * left_sigma_poly;
        let a_1 = w_l_gamma_poly + &beta_left_sigma;
        assert_eq!(a_1.degree(), n + 1);
        //
        // (b(X) + beta * Sigma2(X) + gamma)
        let beta_right_sigma = &poly_beta * right_sigma_poly;
        let a_2 = w_r_gamma_poly + &beta_right_sigma;
        assert_eq!(a_2.degree(), n + 1);
        //
        //(c(X) + beta * Sigma3(X) + gamma)
        let beta_out_sigma = &poly_beta * out_sigma_poly;
        let a_3 = w_o_gamma_poly + &beta_out_sigma;
        assert_eq!(a_3.degree(), n + 1);

        let mut a = &a_1 * &a_2; //(a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma)
        a = &a * &a_3; // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)
        a = &a * shifted_z_poly; // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma) Z(X.omega)

        a = &a * &alpha_sq_poly; // (a(x) + beta* Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma) Z(X.omega) * alpha^2
        let (q, _) = a.divide_by_vanishing_poly(*domain).unwrap(); // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma) Z(X.omega) * alpha^2 / Z_H

        assert_eq!(q.degree(), 3 * n + 5);
        -q
    }

    fn compute_quotient_fourth_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        z_poly: &Polynomial<E::Fr>,
        alpha_cu_poly: Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let n = domain.size();
        // (Z(x) - 1) * l1(X) / Z_H
        let mut k = z_poly - &Polynomial::from_coefficients_slice(&[E::Fr::from(1)]);
        k = &k * &self.compute_first_lagrange_poly(n);
        k = &k * &alpha_cu_poly;
        k.divide_by_vanishing_poly(*domain).unwrap();
        k
    }

    /// Computes the Lagrange polynomial `L1(X)`.
    /// x^n - 1 / n(x-1)
    pub fn compute_first_lagrange_poly(&self, size: usize) -> Polynomial<E::Fr> {
        let n = E::Fr::from_repr((size as u64).into());

        use ff_fft::{DenseOrSparsePolynomial, SparsePolynomial};

        let numerator_coeffs = vec![(0, -E::Fr::one()), (size, E::Fr::one())];
        let numerator_poly: DenseOrSparsePolynomial<E::Fr> =
            SparsePolynomial::from_coefficients_vec(numerator_coeffs).into();

        let denominator_coeffs = vec![(0, -n), (1, n)];
        let denominator_poly: DenseOrSparsePolynomial<E::Fr> =
            SparsePolynomial::from_coefficients_vec(denominator_coeffs).into();

        let (q, r) = numerator_poly
            .divide_with_q_and_r(&denominator_poly)
            .unwrap();
        assert_eq!(r, Polynomial::zero());

        q
    }

    // Split `t(X)` poly into three degree-n polynomials.
    pub fn split_tx_poly(
        &self,
        n: usize,
        t_x: &Polynomial<E::Fr>,
    ) -> (Polynomial<E::Fr>, Polynomial<E::Fr>, Polynomial<E::Fr>) {
        (
            Polynomial::from_coefficients_slice(&t_x[0..n]),
            Polynomial::from_coefficients_slice(&t_x[n..2 * n]),
            Polynomial::from_coefficients_slice(&t_x[2 * n..]),
        )
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
        let (t_lo, t_mid, t_hi) = toolkit.split_tx_poly(n, &t_x);

        // Evaluate n-degree polynomials
        let t_lo_eval = t_lo.evaluate(rand_point);

        let mut t_mid_eval = t_mid.evaluate(rand_point);
        t_mid_eval = t_mid_eval * &rand_point_n;

        let mut t_hi_eval = t_hi.evaluate(rand_point);
        t_hi_eval = t_hi_eval * &rand_point_2n;

        let mut t_components_eval = t_lo_eval + &t_mid_eval;
        t_components_eval += &t_hi_eval;

        assert_eq!(t_x_eval, t_components_eval);
    }

    #[test]
    fn test_l1_x_poly() {
        let toolkit: QuotientToolkit<E> = QuotientToolkit::new();

        let n = 4;
        let domain = EvaluationDomain::new(n).unwrap();

        use algebra::UniformRand;
        let rand_point = Fr::rand(&mut rand::thread_rng());

        let expected_l1_eval = domain.evaluate_all_lagrange_coefficients(rand_point)[0];
        let q = toolkit.compute_first_lagrange_poly(domain.size());
        let got_l1_eval = q.evaluate(rand_point);

        assert_eq!(expected_l1_eval, got_l1_eval);
        assert_eq!(Fr::one(), q.evaluate(Fr::one()))
    }
}
