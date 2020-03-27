use crate::constraint_system::standard::PreProcessedCircuit;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::permutation::grand_product_lineariser;
use bls12_381::Scalar;

/// Evaluations at points `z` or and `z * root of unity`
pub struct Evaluations {
    pub proof: ProofEvaluations,
    // Evaluation of the linearisation sigma polynomial at `z`
    pub quot_eval: Scalar,
}
// Proof Evaluations is a subset of all of the evaluations. These evaluations will be added to the proof
pub struct ProofEvaluations {
    // Evaluation of the witness polynomial for the left wire at `z`
    pub a_eval: Scalar,
    // Evaluation of the witness polynomial for the right wire at `z`
    pub b_eval: Scalar,
    // Evaluation of the witness polynomial for the output wire at `z`
    pub c_eval: Scalar,
    // Evaluation of the witness polynomial for the fourth wire at `z`
    pub d_eval: Scalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of unity`
    pub d_next_eval: Scalar,
    // Evaluation of the arithmetic selector polynomial at `z`
    pub q_arith_eval: Scalar,

    // Evaluation of the left sigma polynomial at `z`
    pub left_sigma_eval: Scalar,
    // Evaluation of the right sigma polynomial at `z`
    pub right_sigma_eval: Scalar,
    // Evaluation of the out sigma polynomial at `z`
    pub out_sigma_eval: Scalar,

    // Evaluation of the linearisation sigma polynomial at `z`
    pub lin_poly_eval: Scalar,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of unity`
    pub perm_eval: Scalar,
}

/// Compute the linearisation polynomial
pub fn compute(
    domain: &EvaluationDomain,
    preprocessed_circuit: &PreProcessedCircuit,
    (alpha, beta, gamma, z_challenge): &(Scalar, Scalar, Scalar, Scalar),
    w_l_poly: &Polynomial,
    w_r_poly: &Polynomial,
    w_o_poly: &Polynomial,
    w_4_poly: &Polynomial,
    t_x_poly: &Polynomial,
    z_poly: &Polynomial,
) -> (Polynomial, Evaluations) {
    let alpha_sq = alpha.square();

    // Compute evaluations
    let quot_eval = t_x_poly.evaluate(z_challenge);
    let a_eval = w_l_poly.evaluate(z_challenge);
    let b_eval = w_r_poly.evaluate(z_challenge);
    let c_eval = w_o_poly.evaluate(z_challenge);
    let d_eval = w_4_poly.evaluate(z_challenge);
    let left_sigma_eval = preprocessed_circuit.left_sigma_poly().evaluate(z_challenge);
    let right_sigma_eval = preprocessed_circuit
        .right_sigma_poly()
        .evaluate(z_challenge);
    let out_sigma_eval = preprocessed_circuit.out_sigma_poly().evaluate(z_challenge);
    let q_arith_eval = preprocessed_circuit.qarith_poly().evaluate(z_challenge);

    let d_next_eval = w_4_poly.evaluate(&(z_challenge * domain.group_gen));
    let perm_eval = z_poly.evaluate(&(z_challenge * domain.group_gen));

    let f_1 = compute_circuit_satisfiability(
        &a_eval,
        &b_eval,
        &c_eval,
        &d_eval,
        d_next_eval,
        &q_arith_eval,
        preprocessed_circuit.qm_poly(),
        preprocessed_circuit.ql_poly(),
        preprocessed_circuit.qr_poly(),
        preprocessed_circuit.qo_poly(),
        preprocessed_circuit.qc_poly(),
        preprocessed_circuit.q4_poly(),
        preprocessed_circuit.qrange_poly(),
        preprocessed_circuit.qlogic_poly(),
    );

    let f_2 = grand_product_lineariser::compute_identity_polynomial(
        &a_eval,
        &b_eval,
        &c_eval,
        &d_eval,
        &z_challenge,
        &alpha,
        beta,
        gamma,
        &z_poly,
    );

    let f_3 = grand_product_lineariser::compute_copy_polynomial(
        &(a_eval, b_eval, c_eval),
        &perm_eval,
        &left_sigma_eval,
        &right_sigma_eval,
        &out_sigma_eval,
        &(*alpha, *beta, *gamma),
        preprocessed_circuit.fourth_sigma_poly(),
    );

    let f_4 =
        grand_product_lineariser::compute_is_one_polynomial(domain, z_challenge, &alpha_sq, z_poly);

    let mut lin_poly = &f_1 + &f_2;
    lin_poly = &lin_poly + &f_3;
    lin_poly = &lin_poly + &f_4;

    // Evaluate linearisation polynomial at z_challenge
    let lin_poly_eval = lin_poly.evaluate(z_challenge);

    (
        lin_poly,
        Evaluations {
            proof: ProofEvaluations {
                a_eval,
                b_eval,
                c_eval,
                d_eval,
                d_next_eval,
                q_arith_eval,
                left_sigma_eval,
                right_sigma_eval,
                out_sigma_eval,
                lin_poly_eval,
                perm_eval,
            },
            quot_eval,
        },
    )
}

fn compute_circuit_satisfiability(
    a_eval: &Scalar,
    b_eval: &Scalar,
    c_eval: &Scalar,
    d_eval: &Scalar,
    d_next_eval: Scalar,
    q_arith_eval: &Scalar,
    q_m_poly: &Polynomial,
    q_l_poly: &Polynomial,
    q_r_poly: &Polynomial,
    q_o_poly: &Polynomial,
    q_c_poly: &Polynomial,
    q_4_poly: &Polynomial,
    q_range_poly: &Polynomial,
    q_logic_poly: &Polynomial,
) -> Polynomial {
    // Computes f(f-1)(f-2)(f-3)
    let delta = |f: Scalar| -> Scalar {
        let f_1 = f - Scalar::one();
        let f_2 = f - Scalar::from(2);
        let f_3 = f - Scalar::from(3);
        f * f_1 * f_2 * f_3
    };
    let four = Scalar::from(4);

    // (a_eval * b_eval * q_m_poly + a_eval * q_l + b_eval * q_r + c_eval * q_o + d_eval * q_4 + q_c) * q_arith_eval * alpha
    //
    // a_eval * b_eval * q_m_poly
    let ab = a_eval * b_eval;
    let a_0 = q_m_poly * &ab;

    // a_eval * q_l
    let a_1 = q_l_poly * a_eval;

    // b_eval * q_r
    let a_2 = q_r_poly * b_eval;

    //c_eval * q_o
    let a_3 = q_o_poly * c_eval;

    // d_eval * q_4
    let a_4 = q_4_poly * d_eval;

    let mut a = &a_0 + &a_1;
    a = &a + &a_2;
    a = &a + &a_3;
    a = &a + &a_4;
    a = &a + q_c_poly;
    a = &a * q_arith_eval;

    // Delta([c_eval - 4 * d_eval]) + Delta([b_eval - 4 * c_eval]) + Delta([a_eval - 4 * b_eval]) + Delta([d_next_eval - 4 * a_eval]) * Q_Range(X)
    let b_1 = delta(c_eval - four * d_eval);
    let b_2 = delta(b_eval - four * c_eval);
    let b_3 = delta(a_eval - four * b_eval);
    let b_4 = delta(d_next_eval - four * a_eval);
    let b = q_range_poly * &(b_1 + b_2 + b_3 + b_4);

    let c = q_logic_poly * &((a_eval - b_eval) * c_eval);

    &(&a + &b) + &c
}
