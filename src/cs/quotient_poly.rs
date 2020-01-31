use crate::cs::poly_utils::Poly_utils;
use crate::cs::PreProcessedCircuit;
use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use rayon::prelude::*;
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
        z_coeffs: &[E::Fr],
        witness_polynomials: [&Vec<E::Fr>; 3],
        public_inputs_coeffs: &Vec<E::Fr>,
        (alpha, beta, gamma): &(E::Fr, E::Fr, E::Fr),
    ) -> Vec<E::Fr> {
        let poly_utils: Poly_utils<E> = Poly_utils::new();
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from_repr(13.into());

        let wl_coeffs = witness_polynomials[0];
        let wr_coeffs = witness_polynomials[1];
        let wo_coeffs = witness_polynomials[2];

        // Compute components for t(X)
        let t_1 = self.compute_quotient_first_component(
            domain,
            alpha,
            preprocessed_circuit.qm_eval_4n(),
            preprocessed_circuit.ql_eval_4n(),
            preprocessed_circuit.qr_eval_4n(),
            preprocessed_circuit.qo_eval_4n(),
            preprocessed_circuit.qc_eval_4n(),
            public_inputs_coeffs,
            wl_coeffs,
            wr_coeffs,
            wo_coeffs,
        );
        let t_2 = self.compute_quotient_second_component(
            domain,
            &alpha.square(),
            &k1,
            &k2,
            beta,
            gamma,
            &z_coeffs,
            &wl_coeffs,
            &wr_coeffs,
            &wo_coeffs,
        );
        let mut t_3 = self.compute_quotient_third_component(
            domain,
            &alpha.square(),
            beta,
            gamma,
            &z_coeffs,
            &wl_coeffs,
            &wr_coeffs,
            &wo_coeffs,
            preprocessed_circuit.left_sigma_poly(),
            preprocessed_circuit.right_sigma_poly(),
            preprocessed_circuit.out_sigma_poly(),
        );
        t_3 = poly_utils.add_poly_vectors(&t_2, &t_3);
        t_3 = poly_utils.add_poly_vectors(&t_1, &t_3);
        let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
        domain_4n.ifft_in_place(&mut t_3);

        let grand_product_poly = Polynomial::from_coefficients_vec(t_3);
        let (t_2_3, _) = grand_product_poly
            .divide_by_vanishing_poly(*domain)
            .unwrap();
        let t_4 =
            self.compute_quotient_fourth_component(domain, &z_coeffs, alpha.square() * &alpha);

        let result = &t_2_3 + &t_4;
        result.coeffs
    }

    fn compute_quotient_first_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        alpha: &E::Fr,
        qm_eval_4n: &[E::Fr],
        ql_eval_4n: &[E::Fr],
        qr_eval_4n: &[E::Fr],
        qo_eval_4n: &[E::Fr],
        qc_eval_4n: &[E::Fr],
        pi_coeffs: &[E::Fr],
        wl_coeffs: &[E::Fr],
        wr_coeffs: &[E::Fr],
        wo_coeffs: &[E::Fr],
    ) -> Vec<E::Fr> {
        let n = domain.size();
        let domain_4n = EvaluationDomain::new(4 * n).unwrap();

        let pi_eval_4n = domain_4n.fft(pi_coeffs);

        let wl_eval_4n = domain_4n.fft(&wl_coeffs);
        let wr_eval_4n = domain_4n.fft(&wr_coeffs);
        let wo_eval_4n = domain_4n.fft(&wo_coeffs);

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
                let mut a_1 = *wl * wr;
                a_1 = a_1 * &qm_alpha;
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

        t_1
    }

    fn compute_quotient_second_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        alpha_sq: &E::Fr,
        k1: &E::Fr,
        k2: &E::Fr,
        beta: &E::Fr,
        gamma: &E::Fr,
        z_coeffs: &[E::Fr],
        wl_coeffs: &[E::Fr],
        wr_coeffs: &[E::Fr],
        wo_coeffs: &[E::Fr],
    ) -> Vec<E::Fr> {
        let n = domain.size();
        let domain_4n = EvaluationDomain::new(4 * n).unwrap();

        // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)
        let mut a = wl_coeffs.to_vec();
        a[0] = a[0] + gamma;
        a[1] = a[1] + beta;

        let mut b = wr_coeffs.to_vec();
        b[0] = b[0] + gamma;
        let beta_k1 = *beta * k1;
        b[1] = b[1] + &beta_k1;

        let mut c = wo_coeffs.to_vec();
        c[0] = c[0] + gamma;
        let beta_k2 = *beta * k2;
        c[1] = c[1] + &beta_k2;

        domain_4n.fft_in_place(&mut a);
        domain_4n.fft_in_place(&mut b);
        domain_4n.fft_in_place(&mut c);

        let z_eval_4n = domain_4n.fft(&z_coeffs);

        let t_2: Vec<_> = (0..domain_4n.size())
            .into_par_iter()
            .map(|i| {
                let z = &z_eval_4n[i];

                let mut product = a[i] * &b[i] * &c[i]; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)
                product = product * z; // (a(x) + beta * X + gamma) (b(X) + beta * k1 * X + gamma) (c(X) + beta * k2 * X + gamma)z(X) * alpha^2

                product * alpha_sq
            })
            .collect();
        t_2
    }

    fn compute_quotient_third_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        alpha_sq: &E::Fr,
        beta: &E::Fr,
        gamma: &E::Fr,
        z_coeffs: &[E::Fr],
        wl_coeffs: &[E::Fr],
        wr_coeffs: &[E::Fr],
        wo_coeffs: &[E::Fr],
        left_sigma_coeffs: &[E::Fr],
        right_sigma_coeffs: &[E::Fr],
        out_sigma_coeffs: &[E::Fr],
    ) -> Vec<E::Fr> {
        let n = domain.size();
        let poly_utils: Poly_utils<E> = Poly_utils::new();
        let domain_4n = EvaluationDomain::new(4 * n).unwrap();

        // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)
        //
        let beta_left_sigma: Vec<_> = left_sigma_coeffs.par_iter().map(|x| *beta * x).collect();
        let beta_right_sigma: Vec<_> = right_sigma_coeffs.par_iter().map(|x| *beta * x).collect();
        let beta_out_sigma: Vec<_> = out_sigma_coeffs.par_iter().map(|x| *beta * x).collect();
        // (a(x) + beta * Sigma1(X) + gamma)
        //
        let mut a = poly_utils.add_poly_vectors(&beta_left_sigma, wl_coeffs);
        a[0] = a[0] + gamma;
        // (b(X) + beta * Sigma2(X) + gamma)
        //
        let mut b = poly_utils.add_poly_vectors(&beta_right_sigma, wr_coeffs);
        b[0] = b[0] + gamma;
        //(c(X) + beta * Sigma3(X) + gamma)
        //
        let mut c = poly_utils.add_poly_vectors(&beta_out_sigma, wo_coeffs);
        c[0] = c[0] + gamma;

        domain_4n.fft_in_place(&mut a);
        domain_4n.fft_in_place(&mut b);
        domain_4n.fft_in_place(&mut c);

        let mut z_eval_4n = domain_4n.fft(&z_coeffs);
        z_eval_4n.push(z_eval_4n[0]);
        z_eval_4n.push(z_eval_4n[1]);
        z_eval_4n.push(z_eval_4n[2]);
        z_eval_4n.push(z_eval_4n[3]);

        let t_3: Vec<_> = (0..domain_4n.size())
            .into_par_iter()
            .map(|i| {
                let z_shifted = &z_eval_4n[i + 4];

                let mut product = a[i] * &b[i] * &c[i]; // (a(x) + beta * Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma)
                product = product * z_shifted;

                -product * alpha_sq // (a(x) + beta* Sigma1(X) + gamma) (b(X) + beta * Sigma2(X) + gamma) (c(X) + beta * Sigma3(X) + gamma) Z(X.omega) * alpha^2
            })
            .collect();

        t_3
    }

    fn compute_quotient_fourth_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        z_coeffs: &[E::Fr],
        alpha_cu: E::Fr,
    ) -> Polynomial<E::Fr> {
        let n = domain.size();
        let domain_2n = EvaluationDomain::new(2 * n).unwrap();

        let l1_coeffs = self.compute_first_lagrange_poly(n).coeffs;
        let alpha_cu_l1_coeffs: Vec<_> = l1_coeffs.par_iter().map(|x| alpha_cu * x).collect();

        // (Z(x) - 1)
        let mut z_coeffs = z_coeffs.to_vec();
        z_coeffs[0] = z_coeffs[0] - &E::Fr::one();

        let z_evals = domain_2n.fft(&z_coeffs);
        let alpha_cu_l1_evals = domain_2n.fft(&alpha_cu_l1_coeffs);

        let t_4: Vec<_> = (0..domain_2n.size())
            .into_par_iter()
            .map(|i| alpha_cu_l1_evals[i] * &z_evals[i])
            .collect();
        let t_4_poly = Polynomial::from_coefficients_vec(domain_2n.ifft(&t_4));
        let (q, _) = t_4_poly.divide_by_vanishing_poly(*domain).unwrap();
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
}
