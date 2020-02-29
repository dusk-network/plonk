use crate::constraint_system::standard::PreProcessedCircuit;
use crate::fft::{poly_utils, EvaluationDomain, Polynomial};
use bls12_381::Scalar;

/// Evaluations at points `z` or and `z * root of unity`
pub struct Evaluations {
    pub proof: ProofEvaluations,
    // Evaluation of the linearisation sigma polynomial at `z`
    pub quot_eval: Scalar,
}
// Proof Evaluations is a subset of all of the evaluations. These evaluations will be added to the proof
pub struct ProofEvaluations {
    // Evaluation of the witness polynomial for the left wires at `z`
    pub a_eval: Scalar,
    // Evaluation of the witness polynomial for the right wires at `z`
    pub b_eval: Scalar,
    // Evaluation of the witness polynomial for the output wires at `z`
    pub c_eval: Scalar,

    // Evaluation of the left sigma polynomial at `z`
    pub left_sigma_eval: Scalar,
    // Evaluation of the right sigma polynomial at `z`
    pub right_sigma_eval: Scalar,

    // Evaluation of the linearisation sigma polynomial at `z`
    pub lin_poly_eval: Scalar,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of unity`
    pub perm_eval: Scalar,
}

impl Evaluations {
    pub fn as_vec(&self) -> Vec<&Scalar> {
        vec![
            &self.proof.a_eval,
            &self.proof.b_eval,
            &self.proof.c_eval,
            &self.proof.left_sigma_eval,
            &self.proof.right_sigma_eval,
            &self.proof.lin_poly_eval,
            &self.proof.perm_eval,
            &self.quot_eval,
        ]
    }
}

pub fn compute(
    domain: &EvaluationDomain,
    preprocessed_circuit: &PreProcessedCircuit,
    (alpha, beta, gamma, z_challenge): &(Scalar, Scalar, Scalar, Scalar),
    w_l_poly: &Polynomial,
    w_r_poly: &Polynomial,
    w_o_poly: &Polynomial,
    t_x_poly: &Polynomial,
    z_poly: &Polynomial,
) -> (Polynomial, Evaluations) {
    let alpha_sq = alpha.square();
    let alpha_cu = alpha * alpha_sq;

    // Compute batch evaluations
    let evaluations = poly_utils::multi_point_eval(
        vec![
            t_x_poly,
            w_l_poly,
            w_r_poly,
            w_o_poly,
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
    let perm_eval = poly_utils::single_point_eval(z_poly, &(*z_challenge * &domain.group_gen));

    let f_1 = compute_first_component(
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

    let f_2 = compute_second_component(
        a_eval,
        b_eval,
        c_eval,
        *z_challenge,
        alpha_sq,
        *beta,
        *gamma,
        &z_poly,
    );

    let f_3 = compute_third_component(
        (a_eval, b_eval),
        perm_eval,
        left_sigma_eval,
        right_sigma_eval,
        (alpha_sq, *beta, *gamma),
        preprocessed_circuit.out_sigma_poly(),
    );

    let f_4 = compute_fourth_component(domain, *z_challenge, alpha_cu, z_poly);

    let mut lin_coeffs = poly_utils::add_poly_vectors(&f_1, &f_2);
    lin_coeffs = poly_utils::add_poly_vectors(&lin_coeffs, &f_3);
    lin_coeffs = poly_utils::add_poly_vectors(&lin_coeffs, &f_4);
    let lin_poly = Polynomial::from_coefficients_vec(lin_coeffs);

    // Evaluate linearisation polynomial at z_challenge
    let lin_poly_eval = poly_utils::single_point_eval(&lin_poly, z_challenge);

    (
        lin_poly,
        Evaluations {
            proof: ProofEvaluations {
                a_eval,
                b_eval,
                c_eval,
                left_sigma_eval,
                right_sigma_eval,
                lin_poly_eval,
                perm_eval,
            },
            quot_eval,
        },
    )
}

fn compute_first_component(
    alpha: Scalar,
    a_eval: Scalar,
    b_eval: Scalar,
    c_eval: Scalar,
    q_m_poly: &Polynomial,
    q_l_poly: &Polynomial,
    q_r_poly: &Polynomial,
    q_o_poly: &Polynomial,
    q_c_poly: &Polynomial,
) -> Vec<Scalar> {
    // a_eval * b_eval * q_m_poly
    let ab = a_eval * &b_eval;
    let a_0 = poly_utils::mul_scalar_poly(ab, q_m_poly);

    // a_eval * q_l
    let a_1 = poly_utils::mul_scalar_poly(a_eval, q_l_poly);

    // b_eval * q_r
    let a_2 = poly_utils::mul_scalar_poly(b_eval, q_r_poly);

    //c_eval * q_o
    let a_3 = poly_utils::mul_scalar_poly(c_eval, q_o_poly);

    let mut a = poly_utils::add_poly_vectors(&a_0, &a_1);
    a = poly_utils::add_poly_vectors(&a, &a_2);
    a = poly_utils::add_poly_vectors(&a, &a_3);
    a = poly_utils::add_poly_vectors(&a, &q_c_poly);
    poly_utils::mul_scalar_poly(alpha, &a) // (a_eval * b_eval * q_m_poly + a_eval * q_l + b_eval * q_r + c_eval * q_o + q_c) * alpha
}

fn compute_second_component(
    a_eval: Scalar,
    b_eval: Scalar,
    c_eval: Scalar,
    z_challenge: Scalar,
    alpha_sq: Scalar,
    beta: Scalar,
    gamma: Scalar,
    z_poly: &Polynomial,
) -> Vec<Scalar> {
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

    poly_utils::mul_scalar_poly(a, &z_poly) // (a_eval + beta * z_challenge + gamma)(b_eval + beta * k_1 * z_challenge + gamma)(c_eval + beta * k_2 * z_challenge + gamma) * alpha^2 z(X)
}
fn compute_third_component(
    (a_eval, b_eval): (Scalar, Scalar),
    z_eval: Scalar,
    sigma_1_eval: Scalar,
    sigma_2_eval: Scalar,
    (alpha_sq, beta, gamma): (Scalar, Scalar, Scalar),
    out_sigma_poly: &Polynomial,
) -> Vec<Scalar> {
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

    poly_utils::mul_scalar_poly(-a, out_sigma_poly) // -(a_eval + beta * sigma_1 + gamma)(b_eval + beta * sigma_2 + gamma) * beta *z_eval * alpha^2 * Sigma_3(X)
}
fn compute_fourth_component(
    domain: &EvaluationDomain,
    z_challenge: Scalar,
    alpha_cu: Scalar,
    z_coeffs: &Polynomial,
) -> Vec<Scalar> {
    // Evaluate l_1(z)
    let l_1_z = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];

    poly_utils::mul_scalar_poly(l_1_z * &alpha_cu, &z_coeffs)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fft::Polynomial;
    use bls12_381::Scalar as Fr;
    #[test]
    fn test_first_component() {
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
            compute_first_component(alpha, a_eval, b_eval, c_eval, &qm, &ql, &qr, &qo, &qc);

        let mut expected_poly = &qm + &ql;
        expected_poly += &qr;
        expected_poly += &qo;
        expected_poly += &qc;

        assert_eq!(Polynomial::from_coefficients_vec(got_poly), expected_poly);
    }

    #[test]
    fn test_second_component() {
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

        let got_poly = compute_second_component(
            a_eval,
            b_eval,
            c_eval,
            z_challenge,
            alpha,
            beta,
            gamma,
            &z_poly,
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
        let alpha = Fr::one();
        let beta = Fr::one();
        let gamma = Fr::one();

        let a_eval = Fr::one();
        let b_eval = Fr::one();
        let sig1_eval = Fr::one();
        let sig2_eval = Fr::one();
        let z_eval = Fr::one();

        let sig3_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = compute_third_component(
            (a_eval, b_eval),
            z_eval,
            sig1_eval,
            sig2_eval,
            (alpha, beta, gamma),
            &sig3_poly,
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
        let alpha = Fr::one();
        let z_challenge = Scalar::from(123);
        let domain = EvaluationDomain::new(10).unwrap();
        let z_poly = Polynomial::rand(10, &mut rand::thread_rng());

        let got_poly = compute_fourth_component(&domain, z_challenge, alpha, &z_poly);

        let l1_eval = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];
        let l1_eval_poly = Polynomial::from_coefficients_vec(vec![l1_eval]);

        let expected_poly = &z_poly * &l1_eval_poly;

        assert_eq!(Polynomial::from_coefficients_vec(got_poly), expected_poly);
    }
}
