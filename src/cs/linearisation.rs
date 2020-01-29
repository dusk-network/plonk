use super::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::fields::PrimeField;
use algebra::{curves::PairingEngine, fields::Field};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use std::marker::PhantomData;

///The lineariser will be the fourth SNARK
///output in the process. This where
/// will no always alllows

pub struct Lineariser<E: PairingEngine> {
    ///Alpha here is a
    alpha: E::Fr,

    beta: E::Fr,

    gamma: E::Fr,

    z_challenge: E::Fr,

    a_eval: E::Fr,

    b_eval: E::Fr,

    c_eval: E::Fr,

    _engine: PhantomData<E>,
}
impl<E: PairingEngine> Lineariser<E> {
    pub fn new(alpha: &E::Fr, beta: &E::Fr, gamma: &E::Fr, z_challenge: &E::Fr) -> Self {
        Lineariser {
            alpha: *alpha,
            beta: *beta,
            gamma: *gamma,
            z_challenge: *z_challenge,
            a_eval: E::Fr::zero(),
            b_eval: E::Fr::zero(),
            c_eval: E::Fr::zero(),
            _engine: PhantomData,
        }
    }
    pub fn evaluate_linearisation_polynomial(
        &self,
        transcript: &mut dyn TranscriptProtocol<E>,
        domain: &EvaluationDomain<E::Fr>,
        preprocessed_circuit: &PreProcessedCircuit<E>,
        w_l_poly: &Polynomial<E::Fr>,
        w_r_poly: &Polynomial<E::Fr>,
        w_o_poly: &Polynomial<E::Fr>,
        t_x: &Polynomial<E::Fr>,
        z_poly: &Polynomial<E::Fr>,
        shifted_z_poly: &Polynomial<E::Fr>,
    ) -> (Polynomial<E::Fr>, Vec<E::Fr>) {
        let alpha_sq = &self.alpha.square();
        let alpha_cu = self.alpha * &alpha_sq;

        // Evaluate a(x), b(x) and c(x)
        let a_eval = w_l_poly.evaluate(self.z_challenge);
        let b_eval = w_r_poly.evaluate(self.z_challenge);
        let c_eval = w_o_poly.evaluate(self.z_challenge);

        // Evaluate sigma1 and sigma2
        let sig_1_eval =
            Polynomial::from_coefficients_slice(preprocessed_circuit.left_sigma_poly())
                .evaluate(self.z_challenge);
        let sig_2_eval =
            Polynomial::from_coefficients_slice(preprocessed_circuit.right_sigma_poly())
                .evaluate(self.z_challenge);

        // Evaluate quotient poly
        let t_x_1 = Polynomial::from_coefficients_slice(t_x);

        let quot_eval = t_x_1.evaluate(self.z_challenge);

        // Evaluate permutation poly_commit
        let perm_eval = z_poly.evaluate(self.z_challenge * &domain.group_gen);
        assert_eq!(shifted_z_poly.evaluate(self.z_challenge), perm_eval);

        let f_1 = self.compute_first_component(
            &Polynomial::from_coefficients_slice(preprocessed_circuit.qm_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.ql_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.qr_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.qo_poly()),
            &Polynomial::from_coefficients_slice(preprocessed_circuit.qc_poly()),
        );

        let f_2 = self.compute_second_component(*alpha_sq, z_poly);

        let f_3 = self.compute_third_component(
            perm_eval,
            sig_1_eval,
            sig_2_eval,
            *alpha_sq,
            &Polynomial::from_coefficients_slice(preprocessed_circuit.out_sigma_poly()),
        );

        let f_4 = self.compute_fourth_component(domain, alpha_cu, z_poly);

        let mut lin_poly = &f_1 + &f_2;
        lin_poly += &f_3;
        lin_poly += &f_4;

        // Evaluate linearisation polynomial at z_challenge
        let lin_poly_eval = lin_poly.evaluate(self.z_challenge);

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
        )
    }

    fn compute_first_component(
        &self,
        q_m_poly: &Polynomial<E::Fr>,
        q_l_poly: &Polynomial<E::Fr>,
        q_r_poly: &Polynomial<E::Fr>,
        q_o_poly: &Polynomial<E::Fr>,
        q_c_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let poly_a = Polynomial::from_coefficients_vec(vec![self.a_eval]);
        let poly_b = Polynomial::from_coefficients_vec(vec![self.b_eval]);
        let poly_c = Polynomial::from_coefficients_vec(vec![self.c_eval]);
        let poly_alpha = Polynomial::from_coefficients_vec(vec![self.alpha]);

        // a_eval * b_eval * q_m_poly
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
        a = &a * &poly_alpha; // (a_eval * b_eval * q_m_poly + a_eval * q_l + b_eval * q_r + c_eval * q_o + q_c) * alpha

        a
    }

    fn compute_second_component(
        &self,
        alpha_sq: E::Fr,
        z_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from(13.into());

        let beta_z = self.beta * &self.z_challenge;

        // a_eval + beta * z_challenge + gamma
        let mut a_0 = self.a_eval + &beta_z;
        a_0 += &self.gamma;

        // b_eval + beta * k_1 * z_challenge + gamma
        let beta_z_k1 = k1 * &beta_z;
        let mut a_1 = self.b_eval + &beta_z_k1;
        a_1 += &self.gamma;

        // c_eval + beta * k_2 * z_challenge + gamma
        let beta_z_k2 = k2 * &beta_z;
        let mut a_2 = self.c_eval + &beta_z_k2;
        a_2 += &self.gamma;

        let mut a = a_0 * &a_1;
        a = a * &a_2;
        a = a * &alpha_sq; // (a_eval + beta * z_challenge + gamma)(b_eval + beta * k_1 * z_challenge + gamma)(c_eval + beta * k_2 * z_challenge + gamma) * alpha^2

        let poly_a = Polynomial::from_coefficients_vec(vec![a]);

        &poly_a * z_poly
    }
    fn compute_third_component(
        &self,
        z_eval: E::Fr,
        sigma_1_eval: E::Fr,
        sigma_2_eval: E::Fr,
        alpha_sq: E::Fr,
        out_sigma_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        // a_eval + beta * sigma_1 + gamma
        let beta_sigma_1 = self.beta * &sigma_1_eval;
        let mut a_0 = self.a_eval + &beta_sigma_1;
        a_0 += &self.gamma;

        // b_eval + beta * sigma_2 + gamma
        let beta_sigma_2 = self.beta * &sigma_2_eval;
        let mut a_1 = self.b_eval + &beta_sigma_2;
        a_1 += &self.gamma;

        let beta_z_eval = self.beta * &z_eval;

        let mut a = a_0 * &a_1;
        a = a * &beta_z_eval;
        a = a * &alpha_sq; // (a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma) * beta *z_eval * alpha^2

        let poly_a = Polynomial::from_coefficients_vec(vec![a]);

        -(&poly_a * out_sigma_poly)
    }
    fn compute_fourth_component(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        alpha_cu: E::Fr,
        z_poly: &Polynomial<E::Fr>,
    ) -> Polynomial<E::Fr> {
        // Evaluate l_1(z)
        let l_1_z = domain.evaluate_all_lagrange_coefficients(self.z_challenge)[0];

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
    use std::str::FromStr;
    #[test]
    fn test_first_component() {
        let alpha = Fr::one();
        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let c_eval = Fr::one();
        let lin: Lineariser<E> = Lineariser::new(&alpha, &Fr::zero(), &Fr::zero(), &Fr::zero());

        let qm = Polynomial::rand(10, &mut rand::thread_rng());
        let ql = Polynomial::rand(10, &mut rand::thread_rng());
        let qr = Polynomial::rand(10, &mut rand::thread_rng());
        let qo = Polynomial::rand(10, &mut rand::thread_rng());
        let qc = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_first_component(&qm, &ql, &qr, &qo, &qc);

        let mut expected_poly = &qm + &ql;
        expected_poly += &qr;
        expected_poly += &qo;
        expected_poly += &qc;

        assert_eq!(got_poly, expected_poly);
    }

    #[test]
    fn test_second_component() {
        let k1 = Fr::multiplicative_generator();
        let k2 = Fr::from_str("13").unwrap();

        let alpha = Fr::one();
        let beta = Fr::one();
        let gamma = Fr::one();

        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let c_eval = Fr::one();
        let z_challenge = Fr::one();
        let alpha_sq = Fr::one();
        let lin: Lineariser<E> = Lineariser::new(&alpha, &beta, &gamma, &z_challenge);
        let z_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_second_component(alpha_sq, &z_poly);

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
        let alpha = Fr::one();
        let beta = Fr::one();
        let gamma = Fr::one();
        let lin: Lineariser<E> = Lineariser::new(&alpha, &beta, &gamma, &Fr::one());

        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let sig1_eval = Fr::one();
        let sig2_eval = Fr::one();
        let z_eval = Fr::one();
        let alpha_sq = Fr::one();

        let sig3_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly =
            lin.compute_third_component(z_eval, sig1_eval, sig2_eval, alpha_sq, &sig3_poly);

        let first_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3 as u8)]);
        let second_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3 as u8)]);
        let third_bracket = Polynomial::from_coefficients_vec(vec![z_eval]);

        let mut expected_poly = &first_bracket * &second_bracket;
        expected_poly = &expected_poly * &third_bracket;
        expected_poly = &expected_poly * &sig3_poly;

        assert_eq!(got_poly, -expected_poly);
    }

    #[test]
    fn test_fourth_component() {
        let alpha = Fr::one();
        let z_challenge = Fr::rand(&mut rand::thread_rng());
        let lin: Lineariser<E> = Lineariser::new(&alpha, &Fr::one(), &Fr::one(), &z_challenge);
        let domain = EvaluationDomain::new(10).unwrap();
        let z_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_fourth_component(&domain, z_challenge, &z_poly);

        let l1_eval = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];
        let l1_eval_poly = Polynomial::from_coefficients_vec(vec![l1_eval]);

        let expected_poly = &z_poly * &l1_eval_poly;

        assert_eq!(got_poly, expected_poly);
    }
}
