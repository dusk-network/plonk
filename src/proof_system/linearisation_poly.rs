// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::widget::ProverKey;
use crate::serialisation::{read_scalar, SerialisationErrors};
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;

/// Evaluations at points `z` or and `z * root of unity`
pub struct Evaluations {
    pub proof: ProofEvaluations,
    // Evaluation of the linearisation sigma polynomial at `z`
    pub quot_eval: BlsScalar,
}

/// Proof Evaluations is a subset of all of the evaluations. These evaluations will be added to the proof
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ProofEvaluations {
    // Evaluation of the witness polynomial for the left wire at `z`
    pub a_eval: BlsScalar,
    // Evaluation of the witness polynomial for the right wire at `z`
    pub b_eval: BlsScalar,
    // Evaluation of the witness polynomial for the output wire at `z`
    pub c_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z`
    pub d_eval: BlsScalar,
    //
    pub a_next_eval: BlsScalar,
    //
    pub b_next_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of unity`
    pub d_next_eval: BlsScalar,
    // Evaluation of the arithmetic selector polynomial at `z`
    pub q_arith_eval: BlsScalar,
    //
    pub q_c_eval: BlsScalar,
    //
    pub q_l_eval: BlsScalar,
    //
    pub q_r_eval: BlsScalar,
    // Evaluation of the left sigma polynomial at `z`
    pub left_sigma_eval: BlsScalar,
    // Evaluation of the right sigma polynomial at `z`
    pub right_sigma_eval: BlsScalar,
    // Evaluation of the out sigma polynomial at `z`
    pub out_sigma_eval: BlsScalar,

    // Evaluation of the linearisation sigma polynomial at `z`
    pub lin_poly_eval: BlsScalar,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of unity`
    pub perm_eval: BlsScalar,
}

impl ProofEvaluations {
    /// Serialises a Proof Evaluation struct to bytes
    pub fn to_bytes(&self) -> [u8; ProofEvaluations::serialised_size()] {
        let mut bytes = [0u8; ProofEvaluations::serialised_size()];

        bytes[0..32].copy_from_slice(&self.a_eval.to_bytes()[..]);
        bytes[32..64].copy_from_slice(&self.b_eval.to_bytes()[..]);
        bytes[64..96].copy_from_slice(&self.c_eval.to_bytes()[..]);
        bytes[96..128].copy_from_slice(&self.d_eval.to_bytes()[..]);
        bytes[128..160].copy_from_slice(&self.a_next_eval.to_bytes()[..]);
        bytes[160..192].copy_from_slice(&self.b_next_eval.to_bytes()[..]);
        bytes[192..224].copy_from_slice(&self.d_next_eval.to_bytes()[..]);
        bytes[224..256].copy_from_slice(&self.q_arith_eval.to_bytes()[..]);
        bytes[256..288].copy_from_slice(&self.q_c_eval.to_bytes()[..]);
        bytes[288..320].copy_from_slice(&self.q_l_eval.to_bytes()[..]);
        bytes[320..352].copy_from_slice(&self.q_r_eval.to_bytes()[..]);
        bytes[352..384].copy_from_slice(&self.left_sigma_eval.to_bytes()[..]);
        bytes[384..416].copy_from_slice(&self.right_sigma_eval.to_bytes()[..]);
        bytes[416..448].copy_from_slice(&self.out_sigma_eval.to_bytes()[..]);
        bytes[448..480].copy_from_slice(&self.lin_poly_eval.to_bytes()[..]);
        bytes[480..512].copy_from_slice(&self.perm_eval.to_bytes()[..]);

        bytes
    }
    /// Deserialises a slice of bytes into a proof Evaluation struct
    pub fn from_bytes(bytes: &[u8]) -> Result<ProofEvaluations, SerialisationErrors> {
        if bytes.len() != ProofEvaluations::serialised_size() {
            return Err(SerialisationErrors::NotEnoughBytes);
        }

        let (a_eval, rest) = read_scalar(bytes)?;
        let (b_eval, rest) = read_scalar(rest)?;
        let (c_eval, rest) = read_scalar(rest)?;
        let (d_eval, rest) = read_scalar(rest)?;
        let (a_next_eval, rest) = read_scalar(rest)?;
        let (b_next_eval, rest) = read_scalar(rest)?;
        let (d_next_eval, rest) = read_scalar(rest)?;
        let (q_arith_eval, rest) = read_scalar(rest)?;
        let (q_c_eval, rest) = read_scalar(rest)?;
        let (q_l_eval, rest) = read_scalar(rest)?;
        let (q_r_eval, rest) = read_scalar(rest)?;
        let (left_sigma_eval, rest) = read_scalar(rest)?;
        let (right_sigma_eval, rest) = read_scalar(rest)?;
        let (out_sigma_eval, rest) = read_scalar(rest)?;
        let (lin_poly_eval, rest) = read_scalar(rest)?;
        let (perm_eval, _) = read_scalar(rest)?;

        let proof_evals = ProofEvaluations {
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
        };
        Ok(proof_evals)
    }

    pub const fn serialised_size() -> usize {
        const NUM_SCALARS: usize = 16;
        const SCALAR_SIZE: usize = 32;
        NUM_SCALARS * SCALAR_SIZE
    }
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
    let q_l_eval = prover_key.fixed_base.q_l.0.evaluate(z_challenge);
    let q_r_eval = prover_key.fixed_base.q_r.0.evaluate(z_challenge);

    let a_next_eval = w_l_poly.evaluate(&(z_challenge * domain.group_gen));
    let b_next_eval = w_r_poly.evaluate(&(z_challenge * domain.group_gen));
    let d_next_eval = w_4_poly.evaluate(&(z_challenge * domain.group_gen));
    let perm_eval = z_poly.evaluate(&(z_challenge * domain.group_gen));

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

    let d = prover_key.fixed_base.compute_linearisation(
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

    let e = prover_key.variable_base.compute_linearisation(
        var_base_separation_challenge,
        a_eval,
        a_next_eval,
        b_eval,
        b_next_eval,
        c_eval,
        d_eval,
        d_next_eval,
    );

    let mut linearisation_poly = &a + &b;
    linearisation_poly += &c;
    linearisation_poly += &d;
    linearisation_poly += &e;

    linearisation_poly
}
