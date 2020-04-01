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
    //
    pub a_next_eval: Scalar,
    //
    pub b_next_eval: Scalar,
    //
    pub c_next_eval: Scalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of unity`
    pub d_next_eval: Scalar,
    // Evaluation of the arithmetic selector polynomial at `z`
    pub q_arith_eval: Scalar,
    //
    pub q_c_eval: Scalar,
    //
    pub q_logic_eval: Scalar,
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
    let q_c_eval = preprocessed_circuit.qc_poly().evaluate(z_challenge);
    let q_logic_eval = preprocessed_circuit.qlogic_poly().evaluate(z_challenge);

    let a_next_eval = w_l_poly.evaluate(&(z_challenge * domain.group_gen));
    let b_next_eval = w_r_poly.evaluate(&(z_challenge * domain.group_gen));
    let c_next_eval = w_o_poly.evaluate(&(z_challenge * domain.group_gen));
    let d_next_eval = w_4_poly.evaluate(&(z_challenge * domain.group_gen));
    let perm_eval = z_poly.evaluate(&(z_challenge * domain.group_gen));

    let f_1 = compute_circuit_satisfiability(
        &a_eval,
        &b_eval,
        &c_eval,
        &d_eval,
        &a_next_eval,
        &b_next_eval,
        &c_next_eval,
        &d_next_eval,
        &q_arith_eval,
        &q_c_eval,
        &q_logic_eval,
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
                a_next_eval,
                b_next_eval,
                c_next_eval,
                d_next_eval,
                q_arith_eval,
                q_c_eval,
                q_logic_eval,
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
    a_next_eval: &Scalar,
    b_next_eval: &Scalar,
    c_next_eval: &Scalar,
    d_next_eval: &Scalar,
    q_arith_eval: &Scalar,
    q_c_eval: &Scalar,
    q_logic_eval: &Scalar,
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

    let c_1 = (a_next_eval - b_next_eval) * c_eval;
    let c_2 = delta(a_next_eval - a_eval * four)
        + delta(b_next_eval - b_eval * four)
        + delta(d_next_eval - d_eval * four);
    let c_3 = {
        let six = Scalar::from(6u64);
        let eighty_one = Scalar::from(81u64);
        let eighty_three = Scalar::from(83u64);
        let mut delta_sum: Scalar;
        let mut delta_sq_sum: Scalar;
        let mut T0: Scalar;
        let mut T1: Scalar;
        let mut T2: Scalar;
        let mut T3: Scalar;
        let mut T4: Scalar;
        let mut identity: Scalar;

        // T0 = a
        T0 = a_eval.double();
        T0 = T0.double();
        T0 = a_next_eval - T0;

        // T1 = b
        T1 = b_eval.double();
        T1 = T1.double();
        T1 = b_next_eval - T1;

        // delta_sum = a + b
        delta_sum = T0 + T1;

        // T2 = a^2
        T2 = T0 * T0;
        // T3 = b^2
        T3 = T1 * T1;

        delta_sq_sum = T2 + T3;
        // identity = a^2 + b^2 + 2ab
        identity = delta_sum * delta_sum;
        // identity = 2ab
        identity -= delta_sq_sum;

        // identity = 2(ab - w)
        T4 = c_eval.double();
        identity -= T4;
        // identity *= alpha; XXX: What happens with alphas now?

        // T4 = 4w
        T4 += T4;

        // T2 = a^2 - a
        T2 -= T0;

        // T0 = a^2 - 5a + 6
        T0 += T0;
        T0 += T0;
        T0 = T2 - T0;
        T0 += six;

        // identity = (identity + a(a - 1)(a - 2)(a - 3)) * alpha
        T0 *= T2;
        identity += T0;
        // identity *= alpha; XXX: What happens with alphas now?

        // T3 = b^2 - b
        T3 -= T1;

        // T1 = b^2 - 5b + 6
        T1 += T1;
        T1 += T1;
        T1 = T3 - T1;
        T1 += six;

        // identity = (identity + b(b - 1)(b - 2)(b - 3)) * alpha
        T1 *= T3;
        identity += T1;
        // identity *= alpha; XXX: What happens with alphas now?

        // T0 = 3(a + b)
        T0 = delta_sum + delta_sum;
        T0 += delta_sum;

        // T1 = 9(a + b)
        T1 = T0 + T0;
        T1 += T0;

        // delta_sum = 18(a + b)
        delta_sum = T1 + T1;

        // T1 = 81(a + b)
        T2 = delta_sum + delta_sum;
        T2 += T2;
        T1 += T2;

        // delta_squared_sum = 18(a^2 + b^2)
        T2 = delta_sq_sum + delta_sq_sum;
        T2 += delta_sq_sum;
        delta_sq_sum = T2 + T2;
        delta_sq_sum += T2;
        delta_sq_sum += delta_sq_sum;

        // delta_sum = w(4w - 18(a + b) + 81)
        delta_sum = T4 - delta_sum;
        delta_sum += eighty_one;
        delta_sum *= c_eval;

        // T1 = 18(a^2 + b^2) - 81(a + b) + 83
        T1 = delta_sq_sum - T1;
        T1 += eighty_three;

        // delta_sum = w ( w ( 4w - 18(a + b) + 81) + 18(a^2 + b^2) - 81(a + b) + 83)
        delta_sum += T1;
        delta_sum *= c_eval;

        // T2 = 3c
        T2 = d_eval.double();
        T2 += T2;
        T2 = d_next_eval - T2;
        T3 = T2 + T2;
        T2 += T3;

        // T3 = 9c
        T3 = T2 + T2;
        T3 += T2;

        // T3 = q_c * (9c - 3(a + b))
        T3 -= T0;
        T3 *= q_c_eval;

        // T2 = 3c + 3(a + b) - 2 * delta_sum
        T2 += T0;
        delta_sum += delta_sum;
        T2 -= delta_sum;

        // T2 = T2 + T3
        T2 += T3;

        // identity = q_logic * alpha_base * (identity + T2)
        identity += T2;
        // identity *= alpha_base;
        identity *= q_logic_eval;

        identity
    };
    let c = q_logic_poly * &(c_1 + c_2 + c_3);

    &(&a + &b) + &c
}
