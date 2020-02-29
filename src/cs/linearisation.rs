use super::PreProcessedCircuit;
use crate::cs::poly_utils::Poly_utils;
use crate::fft::EvaluationDomain;
use bls12_381::Scalar;

pub struct Lineariser {}

pub struct LinEval {
    pub a_eval: Scalar,
    pub b_eval: Scalar,
    pub c_eval: Scalar,
    pub left_sigma_eval: Scalar,
    pub right_sigma_eval: Scalar,
    pub quot_eval: Scalar,
    pub lin_poly_eval: Scalar,
    pub perm_eval: Scalar,
}

impl Into<Vec<Scalar>> for LinEval {
    fn into(self) -> Vec<Scalar> {
        vec![
            self.a_eval,
            self.b_eval,
            self.c_eval,
            self.left_sigma_eval,
            self.right_sigma_eval,
            self.quot_eval,
            self.lin_poly_eval,
            self.perm_eval,
        ]
    }
}

impl LinEval {
    pub fn to_vec(self) -> Vec<Scalar> {
        self.into()
    }
}

impl Lineariser {
    pub fn new() -> Self {
        Lineariser {}
    }
    pub fn evaluate_linearisation_polynomial(
        &self,
        domain: &EvaluationDomain,
        preprocessed_circuit: &PreProcessedCircuit,
        (alpha, beta, gamma, z_challenge): &(Scalar, Scalar, Scalar, Scalar),
        w_l_coeffs: &Vec<Scalar>,
        w_r_coeffs: &Vec<Scalar>,
        w_o_coeffs: &Vec<Scalar>,
        t_x_coeffs: &Vec<Scalar>,
        z_coeffs: &Vec<Scalar>,
    ) -> (Vec<Scalar>, LinEval) {
        let poly_utils: Poly_utils = Poly_utils::new();
        let alpha_sq = alpha.square();
        let alpha_cu = alpha * alpha_sq;

        // Compute batch evaluations
        let evaluations = poly_utils.multi_point_eval(
            vec![
                t_x_coeffs,
                w_l_coeffs,
                w_r_coeffs,
                w_o_coeffs,
                preprocessed_circuit.left_sigma_poly(),
                preprocessed_circuit.right_sigma_poly(),
            ],
            z_challenge,
        );
        let quot_eval = evaluations[0];
        let a_eval = evaluations[1];
        let b_eval = evaluations[2];
        let c_eval = evaluations[3];
        let left_sigma_eval = evaluations[4];
        let right_sigma_eval = evaluations[5];

        // Compute permutation evaluation point
        let perm_eval = poly_utils.single_point_eval(z_coeffs, &(*z_challenge * &domain.group_gen));

        let f_1 = self.compute_first_component(
            *alpha,
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
            *z_challenge,
            alpha_sq,
            *beta,
            *gamma,
            &z_coeffs,
        );

        let f_3 = self.compute_third_component(
            (a_eval, b_eval),
            perm_eval,
            left_sigma_eval,
            right_sigma_eval,
            (alpha_sq, *beta, *gamma),
            preprocessed_circuit.out_sigma_poly(),
        );

        let f_4 = self.compute_fourth_component(domain, *z_challenge, alpha_cu, &z_coeffs);

        let mut lin_coeffs = poly_utils.add_poly_vectors(&f_1, &f_2);
        lin_coeffs = poly_utils.add_poly_vectors(&lin_coeffs, &f_3);
        lin_coeffs = poly_utils.add_poly_vectors(&lin_coeffs, &f_4);

        // Evaluate linearisation polynomial at z_challenge
        let lin_poly_eval = poly_utils.single_point_eval(&lin_coeffs, z_challenge);

        (
            lin_coeffs,
            LinEval {
                a_eval,
                b_eval,
                c_eval,
                left_sigma_eval,
                right_sigma_eval,
                quot_eval,
                lin_poly_eval,
                perm_eval,
            },
        )
    }

    fn compute_first_component(
        &self,
        alpha: Scalar,
        a_eval: Scalar,
        b_eval: Scalar,
        c_eval: Scalar,
        q_m_poly: &Vec<Scalar>,
        q_l_poly: &Vec<Scalar>,
        q_r_poly: &Vec<Scalar>,
        q_o_poly: &Vec<Scalar>,
        q_c_poly: &Vec<Scalar>,
    ) -> Vec<Scalar> {
        let poly_utils: Poly_utils = Poly_utils::new();

        // a_eval * b_eval * q_m_poly
        let ab = a_eval * &b_eval;
        let a_0 = poly_utils.mul_scalar_poly(ab, q_m_poly);

        // a_eval * q_l
        let a_1 = poly_utils.mul_scalar_poly(a_eval, q_l_poly);

        // b_eval * q_r
        let a_2 = poly_utils.mul_scalar_poly(b_eval, q_r_poly);

        //c_eval * q_o
        let a_3 = poly_utils.mul_scalar_poly(c_eval, q_o_poly);

        let mut a = poly_utils.add_poly_vectors(&a_0, &a_1);
        a = poly_utils.add_poly_vectors(&a, &a_2);
        a = poly_utils.add_poly_vectors(&a, &a_3);
        a = poly_utils.add_poly_vectors(&a, &q_c_poly);
        poly_utils.mul_scalar_poly(alpha, &a) // (a_eval * b_eval * q_m_poly + a_eval * q_l + b_eval * q_r + c_eval * q_o + q_c) * alpha
    }

    fn compute_second_component(
        &self,
        a_eval: Scalar,
        b_eval: Scalar,
        c_eval: Scalar,
        z_challenge: Scalar,
        alpha_sq: Scalar,
        beta: Scalar,
        gamma: Scalar,
        z_coeffs: &Vec<Scalar>,
    ) -> Vec<Scalar> {
        let poly_utils: Poly_utils = Poly_utils::new();

        let k1 = Scalar::from(7);
        let k2 = Scalar::from(13);

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

        poly_utils.mul_scalar_poly(a, &z_coeffs) // (a_eval + beta * z_challenge + gamma)(b_eval + beta * k_1 * z_challenge + gamma)(c_eval + beta * k_2 * z_challenge + gamma) * alpha^2 z(X)
    }
    fn compute_third_component(
        &self,
        (a_eval, b_eval): (Scalar, Scalar),
        z_eval: Scalar,
        sigma_1_eval: Scalar,
        sigma_2_eval: Scalar,
        (alpha_sq, beta, gamma): (Scalar, Scalar, Scalar),
        out_sigma_coeffs: &Vec<Scalar>,
    ) -> Vec<Scalar> {
        let poly_utils = Poly_utils::new();

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

        poly_utils.mul_scalar_poly(-a, out_sigma_coeffs) // -(a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma) * beta *z_eval * alpha^2 * Sigma_3(X)
    }
    fn compute_fourth_component(
        &self,
        domain: &EvaluationDomain,
        z_challenge: Scalar,
        alpha_cu: Scalar,
        z_coeffs: &Vec<Scalar>,
    ) -> Vec<Scalar> {
        let poly_utils = Poly_utils::new();

        // Evaluate l_1(z)
        let l_1_z = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];

        poly_utils.mul_scalar_poly(l_1_z * &alpha_cu, &z_coeffs)
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::fft::Polynomial;
    use bls12_381::Scalar as Fr;
    #[test]
    fn test_first_component() {
        let lin: Lineariser = Lineariser::new();

        let alpha = Fr::one();
        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let c_eval = Fr::one();

        let qm = Polynomial::rand(10, &mut rand::thread_rng());
        let ql = Polynomial::rand(10, &mut rand::thread_rng());
        let qr = Polynomial::rand(10, &mut rand::thread_rng());
        let qo = Polynomial::rand(10, &mut rand::thread_rng());
        let qc = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_first_component(
            alpha, a_eval, b_eval, c_eval, &qm.coeffs, &ql.coeffs, &qr.coeffs, &qo.coeffs,
            &qc.coeffs,
        );

        let mut expected_poly = &qm + &ql;
        expected_poly += &qr;
        expected_poly += &qo;
        expected_poly += &qc;

        assert_eq!(Polynomial::from_coefficients_vec(got_poly), expected_poly);
    }

    #[test]
    fn test_second_component() {
        let lin: Lineariser = Lineariser::new();

        let k1 = Fr::from(7);
        let k2 = Fr::from(13);

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
            &z_poly.coeffs,
        );

        let first_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3)]);
        let second_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(2) + &k1]);
        let third_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(2) + &k2]);

        let mut expected_poly = &first_bracket * &second_bracket;
        expected_poly = &expected_poly * &third_bracket;
        expected_poly = &expected_poly * &z_poly;

        assert_eq!(Polynomial::from_coefficients_vec(got_poly), expected_poly);
    }
    #[test]
    fn test_third_component() {
        let lin: Lineariser = Lineariser::new();

        let alpha = Fr::one();
        let beta = Fr::one();
        let gamma = Fr::one();

        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let sig1_eval = Fr::one();
        let sig2_eval = Fr::one();
        let z_eval = Fr::one();

        let sig3_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_third_component(
            (a_eval, b_eval),
            z_eval,
            sig1_eval,
            sig2_eval,
            (alpha, beta, gamma),
            &sig3_poly.coeffs,
        );

        let first_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3)]);
        let second_bracket = Polynomial::from_coefficients_vec(vec![Fr::from(3)]);
        let third_bracket = Polynomial::from_coefficients_vec(vec![z_eval]);

        let mut expected_poly = &first_bracket * &second_bracket;
        expected_poly = &expected_poly * &third_bracket;
        expected_poly = &expected_poly * &sig3_poly;

        assert_eq!(Polynomial::from_coefficients_vec(got_poly), -expected_poly);
    }
    #[test]
    fn test_fourth_component() {
        let lin: Lineariser = Lineariser::new();

        let alpha = Fr::one();
        let z_challenge = Scalar::from(123);
        let domain = EvaluationDomain::new(10).unwrap();
        let z_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = lin.compute_fourth_component(&domain, z_challenge, alpha, &z_poly.coeffs);

        let l1_eval = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];
        let l1_eval_poly = Polynomial::from_coefficients_vec(vec![l1_eval]);

        let expected_poly = &z_poly * &l1_eval_poly;

        assert_eq!(Polynomial::from_coefficients_vec(got_poly), expected_poly);
    }
}
