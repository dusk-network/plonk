use super::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::fields::PrimeField;
use algebra::{curves::PairingEngine, fields::Field};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use std::marker::PhantomData;

pub struct lineariser<E: PairingEngine> {
    _engine: PhantomData<E>,
}
impl<E: PairingEngine> lineariser<E> {
    pub fn new() -> Self {
        lineariser {
            _engine: PhantomData,
        }
    }
    pub fn evaluate_linearisation_polynomial(
        &self,
        transcript: &mut TranscriptProtocol<E>,
        domain: &EvaluationDomain<E::Fr>,
        preprocessed_circuit: &PreProcessedCircuit<E>,
        alpha: E::Fr,
        beta: E::Fr,
        gamma: E::Fr,
        w_l_poly: &Polynomial<E::Fr>,
        w_r_poly: &Polynomial<E::Fr>,
        w_o_poly: &Polynomial<E::Fr>,
        t_lo: &Polynomial<E::Fr>,
        t_mid: &Polynomial<E::Fr>,
        t_hi: &Polynomial<E::Fr>,
        z_poly: &Polynomial<E::Fr>,
    ) -> (Polynomial<E::Fr>, Vec<E::Fr>, E::Fr) {
        let alpha_sq = alpha.square();
        let alpha_cu = alpha * &alpha_sq;

        let sigma_1_poly =
            Polynomial::from_coefficients_slice(&preprocessed_circuit.left_sigma_poly());
        let sigma_2_poly =
            Polynomial::from_coefficients_slice(&preprocessed_circuit.right_sigma_poly());
        let sigma_3_poly =
            Polynomial::from_coefficients_slice(&preprocessed_circuit.out_sigma_poly());

        // Compute challenge
        let z_challenge = transcript.challenge_scalar(b"z");

        // Evaluate a(x), b(x) and c(x)
        let a_eval = w_l_poly.evaluate(z_challenge);
        let b_eval = w_r_poly.evaluate(z_challenge);
        let c_eval = w_o_poly.evaluate(z_challenge);

        // Evaluate sigma1 and sigma2
        let sig_1_eval = sigma_1_poly.evaluate(z_challenge);
        let sig_2_eval = sigma_2_poly.evaluate(z_challenge);

        // Evaluate quotient poly
        // Evaluate t_lo
        let t_lo_eval = t_lo.evaluate(z_challenge);
        // Evaluate t_mid
        let z_n = z_challenge.pow(&[domain.size() as u64]);
        let t_mid_eval = t_mid.evaluate(z_challenge);
        let quot_mid = z_n * &t_mid_eval;
        // Evaluate t_hi
        let z_two_n = z_challenge.pow(&[2 * domain.size() as u64]);
        let t_hi_eval = t_hi.evaluate(z_challenge);
        let quot_hi = z_two_n * &t_hi_eval;
        //
        let mut quot_eval = t_lo_eval + &quot_mid;
        quot_eval += &quot_hi;

        // Evaluate permutation poly_commit
        let perm_eval = z_poly.evaluate(z_challenge * &domain.group_gen);

        let f_1 = self.compute_first_component(
            alpha,
            a_eval,
            b_eval,
            c_eval,
            preprocessed_circuit.qm_poly(),
            preprocessed_circuit.ql_poly(),
            preprocessed_circuit.qr_poly(),
            preprocessed_circuit.qo_poly(),
            preprocessed_circuit.qc_poly(),
        );

        let f_2 = self.compute_second_component(
            a_eval,
            b_eval,
            c_eval,
            z_challenge,
            alpha_sq,
            beta,
            gamma,
            z_poly,
        );

        let f_3 = self.compute_third_component(
            a_eval,
            b_eval,
            c_eval,
            perm_eval,
            sig_1_eval,
            sig_2_eval,
            alpha_sq,
            beta,
            gamma,
            &sigma_3_poly,
        );

        let f_4 = self.compute_fourth_component(domain, z_challenge, alpha_cu, z_poly);

        let mut lin_poly = &f_1 + &f_2;
        lin_poly -= &f_3;
        lin_poly += &f_4;

        // Evalutate linearisation polynomial at z_challenge
        let lin_poly_eval = lin_poly.evaluate(z_challenge);

        (
            lin_poly,
            vec![
                a_eval,
                b_eval,
                c_eval,
                sig_1_eval,
                sig_2_eval,
                quot_eval,
                lin_poly_eval,
                perm_eval,
            ],
            z_challenge,
        )
    }

    fn compute_first_component(
        &self,
        alpha: E::Fr,
        a_eval: E::Fr,
        b_eval: E::Fr,
        c_eval: E::Fr,
        q_m_poly: &Polynomial<E::Fr>,
        q_l_poly: &Polynomial<E::Fr>,
        q_r_poly: &Polynomial<E::Fr>,
        q_o_poly: &Polynomial<E::Fr>,
        q_c_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let poly_a = Polynomial::from_coefficients_vec(vec![a_eval]);
        let poly_b = Polynomial::from_coefficients_vec(vec![b_eval]);
        let poly_c = Polynomial::from_coefficients_vec(vec![c_eval]);
        let poly_alpha = Polynomial::from_coefficients_vec(vec![alpha]);

        // a_eval * b_eval * q_m_poly
        let ab = a_eval * &b_eval;
        let poly_ab = &poly_a * &poly_b;
        let a_0 = &poly_ab * q_m_poly;

        // a_eval * q_l
        let a_1 = &poly_a * q_l_poly;

        // b_eval * q_r
        let a_2 = &poly_b * q_r_poly;

        //c_eval * q_o
        let a_3 = &poly_c * q_o_poly;

        let mut a = &a_0 + &a_1;
        a += &a_2;
        a += &a_3;
        a += q_c_poly;
        a = &a * &poly_alpha; // (a_eval * b_eval * q_m_poly + a_eval * q_l + b_eval * q_r + c_eval * q_o) * alpha

        a
    }

    fn compute_second_component(
        &self,
        a_eval: E::Fr,
        b_eval: E::Fr,
        c_eval: E::Fr,
        z_challenge: E::Fr,
        alpha_sq: E::Fr,
        beta: E::Fr,
        gamma: E::Fr,
        z_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from_repr(13.into());

        let beta_z = beta * &z_challenge;

        // a_eval + beta * z_challenge + gamma
        let mut a_0 = a_eval + &beta_z;
        a_0 += &gamma;

        // b_eval + beta * k_1 * z_challenge + gamma
        let beta_z_k1 = k1 * &beta_z;
        let mut a_1 = b_eval + &beta_z_k1;
        a_1 += &gamma;

        // c_eval + beta * k_2 * z_challenge + gamma
        let beta_z_k2 = k2 * &beta_z;
        let mut a_2 = c_eval + &beta_z_k2;
        a_2 += &gamma;

        let mut a = a_0 * &a_1;
        a = a * &a_2;
        a = a * &alpha_sq; // (a_eval + beta * z_challenge + gamma)(b_eval + beta * k_1 * z_challenge + gamma)(c_eval + beta * k_2 * z_challenge + gamma) * alpha^2

        let poly_a = Polynomial::from_coefficients_vec(vec![a]);

        &poly_a * z_poly
    }
    fn compute_third_component(
        &self,
        a_eval: E::Fr,
        b_eval: E::Fr,
        c_eval: E::Fr,
        z_eval: E::Fr,
        sigma_1_eval: E::Fr,
        sigma_2_eval: E::Fr,
        alpha_sq: E::Fr,
        beta: E::Fr,
        gamma: E::Fr,
        out_sigma_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        // a_eval + beta * sigma_1 + gamma
        let beta_sigma_1 = beta * &sigma_1_eval;
        let mut a_0 = a_eval + &beta_sigma_1;
        a_0 += &gamma;

        // b_eval + beta * sigma_2 + gamma
        let beta_sigma_2 = beta * &sigma_2_eval;
        let mut a_1 = b_eval + &beta_sigma_2;
        a_1 += &gamma;

        let beta_z_eval = beta * &z_eval;

        let mut a = a_0 * &a_1;
        a = a * &beta_z_eval;
        a = a * &alpha_sq; // (a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma) * beta *z_eval * alpha^2

        let poly_a = Polynomial::from_coefficients_vec(vec![a]);

        &poly_a * out_sigma_poly
    }
    fn compute_fourth_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        z_challenge: E::Fr,
        alpha_cu: E::Fr,
        z_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        // Evaluate l_1(z)
        let l_1_z = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];

        let a = l_1_z * &alpha_cu;

        let poly_a = Polynomial::from_coefficients_vec(vec![a]);

        &poly_a * z_poly
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381 as E;
    use algebra::fields::bls12_381::Fr;
    use algebra::UniformRand;
    #[test]
    fn test_first_component() {
        let lin: lineariser<E> = lineariser::new();

        let alpha = Fr::one();
        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let c_eval = Fr::one();

        let qm = Polynomial::rand(10, &mut rand::thread_rng());
        let ql = Polynomial::rand(10, &mut rand::thread_rng());
        let qr = Polynomial::rand(10, &mut rand::thread_rng());
        let qo = Polynomial::rand(10, &mut rand::thread_rng());
        let qc = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly =
            lin.compute_first_component(alpha, a_eval, b_eval, c_eval, &qm, &ql, &qr, &qo, &qc);

        let mut expected_poly = &qm + &ql;
        expected_poly += &qr;
        expected_poly += &qo;
        expected_poly += &qc;

        assert_eq!(got_poly, expected_poly);
    }

    #[test]
    fn test_second_component() {
        let lin: lineariser<E> = lineariser::new();

        let k1 = Fr::multiplicative_generator();
        let k2 = Fr::from_repr(13.into());

        let alpha = Fr::one();
        let beta = Fr::one();
        let gamma = Fr::one();

        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let c_eval = Fr::one();
        let z_challenge = Fr::one();

        let z_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_second_component(
            a_eval,
            b_eval,
            c_eval,
            z_challenge,
            alpha,
            beta,
            gamma,
            &z_poly,
        );

        let first_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3 as u8)]);
        let second_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(2 as u8) + &k1]);
        let third_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(2 as u8) + &k2]);

        let mut expected_poly = &first_bracket * &second_bracket;
        expected_poly = &expected_poly * &third_bracket;
        expected_poly = &expected_poly * &z_poly;

        assert_eq!(got_poly, expected_poly);
    }
    #[test]
    fn test_third_component() {
        let lin: lineariser<E> = lineariser::new();

        let alpha = Fr::one();
        let beta = Fr::one();
        let gamma = Fr::one();

        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let c_eval = Fr::one();
        let sig1_eval = Fr::one();
        let sig2_eval = Fr::one();
        let z_eval = Fr::one();

        let sig3_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_third_component(
            a_eval, b_eval, c_eval, z_eval, sig1_eval, sig2_eval, alpha, beta, gamma, &sig3_poly,
        );

        let first_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3 as u8)]);
        let second_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3 as u8)]);
        let third_bracket = Polynomial::from_coefficients_vec(vec![z_eval]);

        let mut expected_poly = &first_bracket * &second_bracket;
        expected_poly = &expected_poly * &third_bracket;
        expected_poly = &expected_poly * &sig3_poly;

        assert_eq!(got_poly, expected_poly);
    }
    #[test]
    fn test_fourth_component() {
        let lin: lineariser<E> = lineariser::new();

        let alpha = Fr::one();
        let z_challenge = Fr::rand(&mut rand::thread_rng());
        let domain = EvaluationDomain::new(10).unwrap();
        let z_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_fourth_component(&domain, z_challenge, alpha, &z_poly);

        let l1_eval = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];
        let l1_eval_poly = Polynomial::from_coefficients_vec(vec![l1_eval]);

        let expected_poly = &z_poly * &l1_eval_poly;

        assert_eq!(got_poly, expected_poly);
    }
}
