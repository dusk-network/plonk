use crate::constraint_system::standard::PreProcessedCircuit;
use crate::fft::{EvaluationDomain, Polynomial};
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

#[allow(clippy::too_many_arguments)]
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
    // Compute evaluations
    let quot_eval = t_x_poly.evaluate(z_challenge);
    let a_eval = w_l_poly.evaluate(z_challenge);
    let b_eval = w_r_poly.evaluate(z_challenge);
    let c_eval = w_o_poly.evaluate(z_challenge);
    let d_eval = w_4_poly.evaluate(z_challenge);
    let left_sigma_eval = preprocessed_circuit
        .permutation
        .left_sigma
        .polynomial
        .evaluate(z_challenge);
    let right_sigma_eval = preprocessed_circuit
        .permutation
        .right_sigma
        .polynomial
        .evaluate(z_challenge);
    let out_sigma_eval = preprocessed_circuit
        .permutation
        .out_sigma
        .polynomial
        .evaluate(z_challenge);
    let q_arith_eval = preprocessed_circuit
        .arithmetic
        .q_arith
        .polynomial
        .evaluate(z_challenge);

    let d_next_eval = w_4_poly.evaluate(&(z_challenge * domain.group_gen));
    let perm_eval = z_poly.evaluate(&(z_challenge * domain.group_gen));

    let f_1 = compute_circuit_satisfiability(
        &a_eval,
        &b_eval,
        &c_eval,
        &d_eval,
        d_next_eval,
        &q_arith_eval,
        preprocessed_circuit,
    );

    let f_2 = preprocessed_circuit.permutation.compute_linearisation(
        z_challenge,
        (alpha, beta, gamma),
        (&a_eval, &b_eval, &c_eval, &d_eval),
        (&left_sigma_eval, &right_sigma_eval, &out_sigma_eval),
        &perm_eval,
        z_poly,
    );

    let lin_poly = &f_1 + &f_2;

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
    preprocessed_circuit: &PreProcessedCircuit,
) -> Polynomial {
    let a = preprocessed_circuit.arithmetic.compute_linearisation(
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        q_arith_eval,
    );

    let b = preprocessed_circuit.range.compute_linearisation(
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        &d_next_eval,
    );
    &a + &b
}
