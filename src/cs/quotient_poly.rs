use crate::cs::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use rayon::iter::{
    FromParallelIterator, IndexedParallelIterator, IntoParallelIterator, ParallelIterator,
};
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
        preprocessed_circuit: &PreProcessedCircuit<E>,
        z_poly: &Polynomial<E::Fr>,
        shifted_z_poly: &Polynomial<E::Fr>,
        w_poly: [&Polynomial<E::Fr>; 3],
        (alpha, beta, gamma): &(E::Fr, E::Fr, E::Fr),
    ) -> (Polynomial<E::Fr>) {
        let n = domain.size();
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from_repr(13.into());

        let alpha_poly = Polynomial::from_coefficients_slice(&[*alpha]);
        let alpha_sq_poly = Polynomial::from_coefficients_slice(&[alpha.square()]);
        let alpha_cu_poly = Polynomial::from_coefficients_slice(&[alpha.square() * &alpha]);

        let w_l_poly = w_poly[0];
        let w_r_poly = w_poly[1];
        let w_o_poly = w_poly[2];

        let gamma_poly = Polynomial::from_coefficients_slice(&[*gamma]);
        let w_l_gamma_poly = w_l_poly + &gamma_poly;
        let w_r_gamma_poly = w_r_poly + &gamma_poly;
        let w_o_gamma_poly = w_o_poly + &gamma_poly;

        // Compute components for t(X)
        let t_1 = self.compute_quotient_first_component(
            domain,
            &Polynomial::from_coefficients_slice(preprocessed_circuit.qm_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.ql_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.qr_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.qo_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.qc_poly()),
            alpha_poly,
            w_l_poly,
            w_r_poly,
            w_o_poly,
        );
        let t_2 = self.compute_quotient_second_component(
            domain,
            &alpha_sq_poly,
            &k1,
            &k2,
            beta,
            z_poly,
            &w_l_gamma_poly,
            &w_r_gamma_poly,
            &w_o_gamma_poly,
        );
        let mut t_3 = self.compute_quotient_third_component(
            domain,
            &alpha_sq_poly,
            beta,
            shifted_z_poly,
            &w_l_gamma_poly,
            &w_r_gamma_poly,
            &w_o_gamma_poly,
            &Polynomial::from_coefficients_slice(preprocessed_circuit.left_sigma_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.right_sigma_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.out_sigma_poly()),
        );
        t_3 = &t_2 + &t_3;
        let (t_2_3, _) = Polynomial::from_coefficients_vec(t_3.coeffs)
            .divide_by_vanishing_poly(*domain)
            .unwrap();
        let t_4 = self.compute_quotient_fourth_component(domain, z_poly, alpha_cu_poly);

        &(&t_1 + &t_2_3) + &t_4
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
        let mut a = &a_1 + &a_2; // (a(x)b(x)q_M(x) + a(x)q_L(x)
        a += &a_3; // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x)
        a += &a_4; // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X)
        a += q_c_poly; // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) +  Q_C(X))

        a = &a * &alpha_poly; // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + PI(X) + Q_C(X)) * alpha
        let (q, _) = a.divide_by_vanishing_poly(*domain).unwrap(); // ((a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + Q_C(X)) * alpha) / Z_H

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
        a // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)z(X) * alpha^2
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
        -a // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma) Z(X.omega) * alpha^2
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
        let (q, _) = k.divide_by_vanishing_poly(*domain).unwrap();
        q
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
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381 as E;
    use algebra::fields::bls12_381::Fr;

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
    #[test]
    fn test_lagrange_poly_comp() {
        let toolkit: QuotientToolkit<E> = QuotientToolkit::new();
        let lag_pol = toolkit.compute_first_lagrange_poly(1);
        println!("{:?}", lag_pol);
    }
}
