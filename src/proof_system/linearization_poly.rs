// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{fft::Polynomial, proof_system::ProverKey};

use codec::{Decode, Encode};
use zero_bls12_381::Fr as BlsScalar;
use zero_kzg::Polynomial as ZeroPoly;

/// Evaluations at points `z` or and `z * root of unity`
#[allow(dead_code)]
pub(crate) struct Evaluations {
    pub(crate) proof: ProofEvaluations,
    // Evaluation of the linearization sigma polynomial at `z`
    pub(crate) t_eval: BlsScalar,
}

/// Subset of all of the evaluations. These evaluations
/// are added to the [`Proof`](super::Proof).
#[derive(Debug, Eq, PartialEq, Clone, Default, Decode, Encode)]
pub(crate) struct ProofEvaluations {
    // Evaluation of the witness polynomial for the left wire at `z`
    pub(crate) a_eval: BlsScalar,
    // Evaluation of the witness polynomial for the right wire at `z`
    pub(crate) b_eval: BlsScalar,
    // Evaluation of the witness polynomial for the output wire at `z`
    pub(crate) c_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z`
    pub(crate) d_eval: BlsScalar,
    //
    pub(crate) a_next_eval: BlsScalar,
    //
    pub(crate) b_next_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of
    // unity`
    pub(crate) d_next_eval: BlsScalar,
    // Evaluation of the arithmetic selector polynomial at `z`
    pub(crate) q_arith_eval: BlsScalar,
    //
    pub(crate) q_c_eval: BlsScalar,
    //
    pub(crate) q_l_eval: BlsScalar,
    //
    pub(crate) q_r_eval: BlsScalar,
    //
    // Evaluation of the left sigma polynomial at `z`
    pub(crate) s_sigma_1_eval: BlsScalar,
    // Evaluation of the right sigma polynomial at `z`
    pub(crate) s_sigma_2_eval: BlsScalar,
    // Evaluation of the out sigma polynomial at `z`
    pub(crate) s_sigma_3_eval: BlsScalar,

    // Evaluation of the linearization sigma polynomial at `z`
    pub(crate) r_poly_eval: BlsScalar,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of
    // unity`
    pub(crate) perm_eval: BlsScalar,
}

/// Compute the linearization polynomial.
// TODO: Improve the method signature
#[allow(clippy::type_complexity)]
pub(crate) fn compute(
    group_generator: BlsScalar,
    prover_key: &ProverKey,
    (
        alpha,
        beta,
        gamma,
        range_separation_challenge,
        logic_separation_challenge,
        fixed_base_separation_challenge,
        var_base_separation_challenge,
        z_challenge,
    ): &(
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
    ),
    a_w_poly: &ZeroPoly<BlsScalar>,
    b_w_poly: &ZeroPoly<BlsScalar>,
    c_w_poly: &ZeroPoly<BlsScalar>,
    d_w_poly: &ZeroPoly<BlsScalar>,
    t_x_poly: &ZeroPoly<BlsScalar>,
    z_poly: &Polynomial,
) -> (Polynomial, Evaluations) {
    // Compute evaluations
    let t_eval = t_x_poly.evaluate(z_challenge);
    let a_eval = a_w_poly.evaluate(z_challenge);
    let b_eval = b_w_poly.evaluate(z_challenge);
    let c_eval = c_w_poly.evaluate(z_challenge);
    let d_eval = d_w_poly.evaluate(z_challenge);

    let s_sigma_1_eval =
        prover_key.permutation.s_sigma_1.0.evaluate(z_challenge);
    let s_sigma_2_eval =
        prover_key.permutation.s_sigma_2.0.evaluate(z_challenge);
    let s_sigma_3_eval =
        prover_key.permutation.s_sigma_3.0.evaluate(z_challenge);

    let q_arith_eval = prover_key.arithmetic.q_arith.0.evaluate(z_challenge);
    let q_c_eval = prover_key.logic.q_c.0.evaluate(z_challenge);
    let q_l_eval = prover_key.fixed_base.q_l.0.evaluate(z_challenge);
    let q_r_eval = prover_key.fixed_base.q_r.0.evaluate(z_challenge);

    let a_next_eval = a_w_poly.evaluate(&(z_challenge * group_generator));
    let b_next_eval = b_w_poly.evaluate(&(z_challenge * group_generator));
    let d_next_eval = d_w_poly.evaluate(&(z_challenge * group_generator));
    let perm_eval = z_poly.evaluate(&(z_challenge * group_generator));

    let f_1 = compute_circuit_satisfiability(
        (
            range_separation_challenge,
            logic_separation_challenge,
            fixed_base_separation_challenge,
            var_base_separation_challenge,
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

    let f_2 = prover_key.permutation.compute_linearization(
        z_challenge,
        (alpha, beta, gamma),
        (&a_eval, &b_eval, &c_eval, &d_eval),
        (&s_sigma_1_eval, &s_sigma_2_eval, &s_sigma_3_eval),
        &perm_eval,
        z_poly,
    );

    let r_poly = &f_1 + &f_2;

    // Evaluate linearization polynomial at challenge `z`
    let r_poly_eval = r_poly.evaluate(z_challenge);

    (
        r_poly,
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
                s_sigma_1_eval,
                s_sigma_2_eval,
                s_sigma_3_eval,
                r_poly_eval,
                perm_eval,
            },
            t_eval,
        },
    )
}

fn compute_circuit_satisfiability(
    (
        range_separation_challenge,
        logic_separation_challenge,
        fixed_base_separation_challenge,
        var_base_separation_challenge,
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    a_eval: &BlsScalar,
    b_eval: &BlsScalar,
    c_eval: &BlsScalar,
    d_eval: &BlsScalar,
    a_next_eval: &BlsScalar,
    b_next_eval: &BlsScalar,
    d_next_eval: &BlsScalar,
    q_arith_eval: &BlsScalar,
    q_c_eval: &BlsScalar,
    q_l_eval: &BlsScalar,
    q_r_eval: &BlsScalar,
    prover_key: &ProverKey,
) -> Polynomial {
    let a = prover_key.arithmetic.compute_linearization(
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        q_arith_eval,
    );

    let b = prover_key.range.compute_linearization(
        range_separation_challenge,
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        d_next_eval,
    );

    let c = prover_key.logic.compute_linearization(
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

    let d = prover_key.fixed_base.compute_linearization(
        fixed_base_separation_challenge,
        a_eval,
        a_next_eval,
        b_eval,
        b_next_eval,
        c_eval,
        d_eval,
        d_next_eval,
        q_l_eval,
        q_r_eval,
        q_c_eval,
    );

    let e = prover_key.variable_base.compute_linearization(
        var_base_separation_challenge,
        a_eval,
        a_next_eval,
        b_eval,
        b_next_eval,
        c_eval,
        d_eval,
        d_next_eval,
    );

    let mut linearization_poly = &a + &b;
    linearization_poly += &c;
    linearization_poly += &d;
    linearization_poly += &e;

    linearization_poly
}
