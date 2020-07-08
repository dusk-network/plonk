use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::widget::ProverKey;
use dusk_bls12_381::Scalar;

/// Evaluations at points `z` or and `z * root of unity`
pub struct Evaluations {
    pub proof: ProofEvaluations,
    // Evaluation of the linearisation sigma polynomial at `z`
    pub quot_eval: Scalar,
}

/// Proof Evaluations is a subset of all of the evaluations. These evaluations will be added to the proof
#[derive(Debug, Eq, PartialEq)]
pub struct ProofEvaluations {
    // Evaluation of the witness polynomial for the left wire at `z`
    pub a_eval: Scalar,
    // Evaluation of the witness polynomial for the right wire at `z`
    pub b_eval: Scalar,
    // Evaluation of the witness polynomial for the output wire at `z`
    pub c_eval: Scalar,
    // Evaluation of the witness polynomial for the fourth wire at `z`
    pub d_eval: Scalar,
    //
    pub a_next_eval: Scalar,
    //
    pub b_next_eval: Scalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of unity`
    pub d_next_eval: Scalar,
    // Evaluation of the arithmetic selector polynomial at `z`
    pub q_arith_eval: Scalar,
    //
    pub q_c_eval: Scalar,
    //
    pub q_l_eval: Scalar,
    //
    pub q_r_eval: Scalar,
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
    prover_key: &ProverKey,
    (
        alpha,
        beta,
        gamma,
        range_separation_challenge,
        logic_separation_challenge,
        ecc_separation_challenge,
        z_challenge,
    ): &(Scalar, Scalar, Scalar, Scalar, Scalar, Scalar, Scalar),
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
    let left_sigma_eval = prover_key.permutation.left_sigma.0.evaluate(z_challenge);
    let right_sigma_eval = prover_key.permutation.right_sigma.0.evaluate(z_challenge);
    let out_sigma_eval = prover_key.permutation.out_sigma.0.evaluate(z_challenge);
    let q_arith_eval = prover_key.arithmetic.q_arith.0.evaluate(z_challenge);
    let q_c_eval = prover_key.logic.q_c.0.evaluate(z_challenge);
    let q_l_eval = prover_key.ecc.q_l.0.evaluate(z_challenge);
    let q_r_eval = prover_key.ecc.q_r.0.evaluate(z_challenge);

    let a_next_eval = w_l_poly.evaluate(&(z_challenge * domain.group_gen));
    let b_next_eval = w_r_poly.evaluate(&(z_challenge * domain.group_gen));
    let d_next_eval = w_4_poly.evaluate(&(z_challenge * domain.group_gen));
    let perm_eval = z_poly.evaluate(&(z_challenge * domain.group_gen));

    let f_1 = compute_circuit_satisfiability(
        (
            range_separation_challenge,
            logic_separation_challenge,
            ecc_separation_challenge,
        ),
        &a_eval,
        &b_eval,
        &c_eval,
        &d_eval,
        &a_next_eval,
        &b_next_eval,
        &d_next_eval,
        &q_arith_eval,
        &q_c_eval,
        &q_l_eval,
        &q_r_eval,
        prover_key,
    );

    let f_2 = prover_key.permutation.compute_linearisation(
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
                a_next_eval,
                b_next_eval,
                d_next_eval,
                q_arith_eval,
                q_c_eval,
                q_l_eval,
                q_r_eval,
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

#[allow(clippy::too_many_arguments)]
fn compute_circuit_satisfiability(
    (range_separation_challenge, logic_separation_challenge, ecc_separation_challenge): (
        &Scalar,
        &Scalar,
        &Scalar,
    ),
    a_eval: &Scalar,
    b_eval: &Scalar,
    c_eval: &Scalar,
    d_eval: &Scalar,
    a_next_eval: &Scalar,
    b_next_eval: &Scalar,
    d_next_eval: &Scalar,
    q_arith_eval: &Scalar,
    q_c_eval: &Scalar,
    q_l_eval: &Scalar,
    q_r_eval: &Scalar,
    prover_key: &ProverKey,
) -> Polynomial {
    let a =
        prover_key
            .arithmetic
            .compute_linearisation(a_eval, b_eval, c_eval, d_eval, q_arith_eval);

    let b = prover_key.range.compute_linearisation(
        range_separation_challenge,
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        &d_next_eval,
    );

    let c = prover_key.logic.compute_linearisation(
        logic_separation_challenge,
        a_eval,
        a_next_eval,
        b_eval,
        b_next_eval,
        c_eval,
        d_eval,
        d_next_eval,
        q_c_eval,
    );

    let d = prover_key.ecc.compute_linearisation(
        ecc_separation_challenge,
        a_eval,
        a_next_eval,
        b_eval,
        b_next_eval,
        c_eval,
        d_eval,
        d_next_eval,
        q_l_eval,
        q_r_eval,
    );

    let mut linearisation_poly = &a + &b;
    linearisation_poly += &c;
    linearisation_poly += &d;

    linearisation_poly
}
