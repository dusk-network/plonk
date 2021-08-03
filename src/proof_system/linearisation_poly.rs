// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
use crate::{
    fft::{EvaluationDomain, Polynomial},
    proof_system::ProverKey,
};

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
#[allow(dead_code)]
/// Evaluations at points `z` or and `z * root of unity`
pub(crate) struct Evaluations {
    pub(crate) proof: ProofEvaluations,
    // Evaluation of the linearisation sigma polynomial at `z`
    pub(crate) quot_eval: BlsScalar,
}

/// Subset of all of the evaluations. These evaluations
/// are added to the [`Proof`](super::Proof).
#[derive(Debug, Eq, PartialEq, Clone, Default)]
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
    pub(crate) q_lookup_eval: BlsScalar,
    // Evaluation of the left sigma polynomial at `z`
    pub(crate) left_sigma_eval: BlsScalar,
    // Evaluation of the right sigma polynomial at `z`
    pub(crate) right_sigma_eval: BlsScalar,
    // Evaluation of the out sigma polynomial at `z`
    pub(crate) out_sigma_eval: BlsScalar,

    // Evaluation of the linearisation sigma polynomial at `z`
    pub(crate) lin_poly_eval: BlsScalar,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of
    // unity`
    pub perm_eval: BlsScalar,

    // (Shifted) Evaluation of the lookup permutation polynomial at `z * root
    // of unity`
    pub lookup_perm_eval: BlsScalar,

    /// Evaluations of the first half of sorted plookup poly at `z`
    pub h_1_eval: BlsScalar,

    /// (Shifted) Evaluations of the first half of sorted plookup poly at `z *
    /// root of unity`
    pub h_1_next_eval: BlsScalar,

    /// (Shifted) Evaluations of the second half of sorted plookup poly at `z *
    /// root of unity`
    pub h_2_eval: BlsScalar,

    /// Evaluations of the query polynomial at `z`
    pub f_eval: BlsScalar,

    /// Evaluations of the table polynomial at `z`
    pub table_eval: BlsScalar,

    /// Evaluations of the table polynomial at `z * root of unity`
    pub table_next_eval: BlsScalar,
}

impl Serializable<{ 24 * BlsScalar::SIZE }> for ProofEvaluations {
    type Error = dusk_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;

        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        writer.write(&self.a_eval.to_bytes());
        writer.write(&self.b_eval.to_bytes());
        writer.write(&self.c_eval.to_bytes());
        writer.write(&self.d_eval.to_bytes());
        writer.write(&self.a_next_eval.to_bytes());
        writer.write(&self.b_next_eval.to_bytes());
        writer.write(&self.d_next_eval.to_bytes());
        writer.write(&self.q_arith_eval.to_bytes());
        writer.write(&self.q_c_eval.to_bytes());
        writer.write(&self.q_l_eval.to_bytes());
        writer.write(&self.q_r_eval.to_bytes());
        writer.write(&self.q_lookup_eval.to_bytes());
        writer.write(&self.left_sigma_eval.to_bytes());
        writer.write(&self.right_sigma_eval.to_bytes());
        writer.write(&self.out_sigma_eval.to_bytes());
        writer.write(&self.lin_poly_eval.to_bytes());
        writer.write(&self.perm_eval.to_bytes());
        writer.write(&self.lookup_perm_eval.to_bytes());
        writer.write(&self.h_1_eval.to_bytes());
        writer.write(&self.h_1_next_eval.to_bytes());
        writer.write(&self.h_2_eval.to_bytes());
        writer.write(&self.f_eval.to_bytes());
        writer.write(&self.table_eval.to_bytes());
        writer.write(&self.table_next_eval.to_bytes());

        buf
    }

    fn from_bytes(
        buf: &[u8; Self::SIZE],
    ) -> Result<ProofEvaluations, Self::Error> {
        let mut buffer = &buf[..];
        let a_eval = BlsScalar::from_reader(&mut buffer)?;
        let b_eval = BlsScalar::from_reader(&mut buffer)?;
        let c_eval = BlsScalar::from_reader(&mut buffer)?;
        let d_eval = BlsScalar::from_reader(&mut buffer)?;
        let a_next_eval = BlsScalar::from_reader(&mut buffer)?;
        let b_next_eval = BlsScalar::from_reader(&mut buffer)?;
        let d_next_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_arith_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_c_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_l_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_r_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_lookup_eval = BlsScalar::from_reader(&mut buffer)?;
        let left_sigma_eval = BlsScalar::from_reader(&mut buffer)?;
        let right_sigma_eval = BlsScalar::from_reader(&mut buffer)?;
        let out_sigma_eval = BlsScalar::from_reader(&mut buffer)?;
        let lin_poly_eval = BlsScalar::from_reader(&mut buffer)?;
        let perm_eval = BlsScalar::from_reader(&mut buffer)?;
        let lookup_perm_eval = BlsScalar::from_reader(&mut buffer)?;
        let h_1_eval = BlsScalar::from_reader(&mut buffer)?;
        let h_1_next_eval = BlsScalar::from_reader(&mut buffer)?;
        let h_2_eval = BlsScalar::from_reader(&mut buffer)?;
        let f_eval = BlsScalar::from_reader(&mut buffer)?;
        let table_eval = BlsScalar::from_reader(&mut buffer)?;
        let table_next_eval = BlsScalar::from_reader(&mut buffer)?;

        Ok(ProofEvaluations {
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
            q_lookup_eval,
            left_sigma_eval,
            right_sigma_eval,
            out_sigma_eval,
            lin_poly_eval,
            perm_eval,
            lookup_perm_eval,
            h_1_eval,
            h_1_next_eval,
            h_2_eval,
            f_eval,
            table_eval,
            table_next_eval,
        })
    }
}

#[cfg(feature = "alloc")]

/// Compute the linearisation polynomial.
pub(crate) fn compute(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    (
        alpha,
        beta,
        gamma,
        delta,
        epsilon,
        zeta,
        range_separation_challenge,
        logic_separation_challenge,
        fixed_base_separation_challenge,
        var_base_separation_challenge,
        lookup_separation_challenge,
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
    f_poly: &Polynomial,
    h_1_poly: &Polynomial,
    h_2_poly: &Polynomial,
    table_poly: &Polynomial,
    p_poly: &Polynomial,
) -> (Polynomial, Evaluations) {
    // Compute evaluations
    let quot_eval = t_x_poly.evaluate(z_challenge);
    let a_eval = w_l_poly.evaluate(z_challenge);
    let b_eval = w_r_poly.evaluate(z_challenge);
    let c_eval = w_o_poly.evaluate(z_challenge);
    let d_eval = w_4_poly.evaluate(z_challenge);
    let left_sigma_eval =
        prover_key.permutation.left_sigma.0.evaluate(z_challenge);
    let right_sigma_eval =
        prover_key.permutation.right_sigma.0.evaluate(z_challenge);
    let out_sigma_eval =
        prover_key.permutation.out_sigma.0.evaluate(z_challenge);
    let q_arith_eval = prover_key.arithmetic.q_arith.0.evaluate(z_challenge);
    let q_c_eval = prover_key.logic.q_c.0.evaluate(z_challenge);
    let q_l_eval = prover_key.fixed_base.q_l.0.evaluate(z_challenge);
    let q_r_eval = prover_key.fixed_base.q_r.0.evaluate(z_challenge);
    let q_lookup_eval = prover_key.lookup.q_lookup.0.evaluate(z_challenge);
    let f_eval = f_poly.evaluate(z_challenge);
    let h_1_eval = h_1_poly.evaluate(z_challenge);
    let h_2_eval = h_2_poly.evaluate(z_challenge);
    let table_eval = table_poly.evaluate(z_challenge);

    let a_next_eval = w_l_poly.evaluate(&(z_challenge * domain.group_gen));
    let b_next_eval = w_r_poly.evaluate(&(z_challenge * domain.group_gen));
    let d_next_eval = w_4_poly.evaluate(&(z_challenge * domain.group_gen));
    let perm_eval = z_poly.evaluate(&(z_challenge * domain.group_gen));
    let lookup_perm_eval = p_poly.evaluate(&(z_challenge * domain.group_gen));
    let h_1_next_eval = h_1_poly.evaluate(&(z_challenge * domain.group_gen));
    let table_next_eval =
        table_poly.evaluate(&(z_challenge * domain.group_gen));

    let l_coeffs = domain.evaluate_all_lagrange_coefficients(*z_challenge);
    let l1_eval = l_coeffs[0];

    let f_1 = compute_circuit_satisfiability(
        (
            range_separation_challenge,
            logic_separation_challenge,
            fixed_base_separation_challenge,
            var_base_separation_challenge,
            lookup_separation_challenge,
        ),
        &a_eval,
        &b_eval,
        &c_eval,
        &d_eval,
        &a_next_eval,
        &b_next_eval,
        &d_next_eval,
        &q_arith_eval,
        &f_eval,
        &table_eval,
        &table_next_eval,
        &h_1_eval,
        &h_2_eval,
        &lookup_perm_eval,
        &l1_eval,
        &p_poly,
        &h_2_poly,
        (delta, epsilon),
        zeta,
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
                q_lookup_eval,
                left_sigma_eval,
                right_sigma_eval,
                out_sigma_eval,
                lin_poly_eval,
                perm_eval,
                lookup_perm_eval,
                h_1_eval,
                h_1_next_eval,
                h_2_eval,
                f_eval,
                table_eval,
                table_next_eval,
            },
            quot_eval,
        },
    )
}

#[cfg(feature = "alloc")]
fn compute_circuit_satisfiability(
    (
        range_separation_challenge,
        logic_separation_challenge,
        fixed_base_separation_challenge,
        var_base_separation_challenge,
        lookup_separation_challenge,
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    a_eval: &BlsScalar,
    b_eval: &BlsScalar,
    c_eval: &BlsScalar,
    d_eval: &BlsScalar,
    a_next_eval: &BlsScalar,
    b_next_eval: &BlsScalar,
    d_next_eval: &BlsScalar,
    q_arith_eval: &BlsScalar,
    f_eval: &BlsScalar,
    table_eval: &BlsScalar,
    table_next_eval: &BlsScalar,
    h_1_eval: &BlsScalar,
    h_2_eval: &BlsScalar,
    p_next_eval: &BlsScalar,
    l1_eval: &BlsScalar,
    p_poly: &Polynomial,
    h_2_poly: &Polynomial,
    (delta, epsilon): (&BlsScalar, &BlsScalar),
    zeta: &BlsScalar,
    q_c_eval: &BlsScalar,
    q_l_eval: &BlsScalar,
    q_r_eval: &BlsScalar,
    prover_key: &ProverKey,
) -> Polynomial {
    let a = prover_key.arithmetic.compute_linearisation(
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        q_arith_eval,
    );

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

    let f = prover_key.lookup.compute_linearisation(
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        f_eval,
        table_eval,
        table_next_eval,
        h_1_eval,
        h_2_eval,
        p_next_eval,
        l1_eval,
        p_poly,
        h_2_poly,
        (delta, epsilon),
        zeta,
        lookup_separation_challenge,
    );

    let mut linearisation_poly = &a + &b;
    linearisation_poly += &c;
    linearisation_poly += &d;
    linearisation_poly += &e;
    linearisation_poly += &f;

    linearisation_poly
}

#[cfg(test)]
mod evaluations_tests {
    use super::*;

    #[test]
    fn proof_evaluations_dusk_bytes_serde() {
        let proof_evals = ProofEvaluations::default();
        let bytes = proof_evals.to_bytes();
        let obtained_evals = ProofEvaluations::from_slice(&bytes)
            .expect("Deserialization error");
        assert_eq!(proof_evals.to_bytes(), obtained_evals.to_bytes())
    }
}
