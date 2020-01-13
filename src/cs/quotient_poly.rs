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
        public_input_poly: &Polynomial<E::Fr>,
        (alpha, beta, gamma): &(E::Fr, E::Fr, E::Fr),
    ) -> (Polynomial<E::Fr>, Polynomial<E::Fr>, Polynomial<E::Fr>) {
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
            preprocessed_circuit.qm_poly(),
            preprocessed_circuit.ql_poly(),
            preprocessed_circuit.qr_poly(),
            preprocessed_circuit.qo_poly(),
            preprocessed_circuit.qc_poly(),
            alpha_poly,
            w_l_poly,
            w_r_poly,
            w_o_poly,
            &public_input_poly,
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
        let t_3 = self.compute_quotient_third_component(
            domain,
            &alpha_sq_poly,
            beta,
            shifted_z_poly,
            &w_l_gamma_poly,
            &w_r_gamma_poly,
            &w_o_gamma_poly,
            preprocessed_circuit.left_sigma_poly(),
            preprocessed_circuit.right_sigma_poly(),
            preprocessed_circuit.out_sigma_poly(),
        );
        let t_4 = self.compute_quotient_fourth_component(domain, z_poly, alpha_cu_poly);

        let t_x_0 = &t_1 + &t_2;
        assert_eq!(t_x_0.degree(), 3 * n + 5);
        let t_x_1 = &t_3 + &t_4;
        assert_eq!(t_x_1.degree(), 3 * n + 5);

        // XXX: Adding all components in one variable using AddAsign produces a panic
        let t_x = &t_x_0 + &t_x_1;

        let (t_lo, t_mid, t_hi) = self.split_tx_poly(n, &t_x);
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

    // Evaluates the splited quotient polynomial at a certain point.
    // NOTE that the splited parts are `t_lo`, `t_mid`, `t_hi`.
    pub fn eval_splited_quotient_poly(
        &self,
        split_qp: &[Polynomial<E::Fr>; 3],
        n: usize,
        scalar: &E::Fr,
    ) -> E::Fr {
        let pows = vec![
            E::Fr::one(),
            scalar.pow(&[n as u64]),
            scalar.pow(&[2 * n as u64]),
        ];
        let evaluations: Vec<E::Fr> = split_qp
            .into_par_iter()
            .zip(pows)
            .map(|(poly, pow)| pow * &poly.evaluate(*scalar))
            .collect();
        // Since `Slice<E::Fr>` does not support `Sum()` we add it with
        // a for loop.
        let mut res = E::Fr::zero();
        for eval in &evaluations {
            res = res + eval;
        }
        res
    }

    // Evaluates the quotient polynomial at a certain point.
    pub fn eval_quotient_poly(
        &self,
        quot_poly: &Polynomial<E::Fr>,
        scalar: &E::Fr,
        n: usize,
    ) -> E::Fr {
        let split_qp = {
            let (t_lo, t_mid, t_hi) = self.split_tx_poly(n, &quot_poly);
            [t_lo, t_mid, t_hi]
        };
        self.eval_splited_quotient_poly(&split_qp, n, scalar)
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

        let eval_test = toolkit.eval_quotient_poly(&t_x, &rand_point, n);

        assert_eq!(t_x_eval, t_components_eval);
        assert_eq!(t_x_eval, eval_test);
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
