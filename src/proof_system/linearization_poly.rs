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

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

/// Evaluations at points `z` or and `z * root of unity`
#[allow(dead_code)]
pub(crate) struct Evaluations {
    pub(crate) proof: ProofEvaluations,
    // Evaluation of the linearization sigma polynomial at `z`
    pub(crate) t_eval: BlsScalar,
}

/// Subset of all of the evaluations. These evaluations
/// are added to the [`Proof`](super::Proof).
#[derive(Debug, Eq, PartialEq, Clone, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct ProofEvaluations {
    // Evaluation of the witness polynomial for the left wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_eval: BlsScalar,
    // Evaluation of the witness polynomial for the right wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_eval: BlsScalar,
    // Evaluation of the witness polynomial for the output wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) o_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_next_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_next_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of
    // unity`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_next_eval: BlsScalar,
    // Evaluation of the arithmetic selector polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_arith_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_c_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_l_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_r_eval: BlsScalar,
    //
    // Evaluation of the left sigma polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_1_eval: BlsScalar,
    // Evaluation of the right sigma polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_2_eval: BlsScalar,
    // Evaluation of the out sigma polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_3_eval: BlsScalar,

    // Evaluation of the linearization sigma polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) r_poly_eval: BlsScalar,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of
    // unity`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) z_eval: BlsScalar,
}

// The struct ProofEvaluations has 16 BlsScalars
impl Serializable<{ 16 * BlsScalar::SIZE }> for ProofEvaluations {
    type Error = dusk_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;

        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        writer.write(&self.a_eval.to_bytes());
        writer.write(&self.b_eval.to_bytes());
        writer.write(&self.o_eval.to_bytes());
        writer.write(&self.d_eval.to_bytes());
        writer.write(&self.a_next_eval.to_bytes());
        writer.write(&self.b_next_eval.to_bytes());
        writer.write(&self.d_next_eval.to_bytes());
        writer.write(&self.q_arith_eval.to_bytes());
        writer.write(&self.q_c_eval.to_bytes());
        writer.write(&self.q_l_eval.to_bytes());
        writer.write(&self.q_r_eval.to_bytes());
        writer.write(&self.s_sigma_1_eval.to_bytes());
        writer.write(&self.s_sigma_2_eval.to_bytes());
        writer.write(&self.s_sigma_3_eval.to_bytes());
        writer.write(&self.r_poly_eval.to_bytes());
        writer.write(&self.z_eval.to_bytes());

        buf
    }

    fn from_bytes(
        buf: &[u8; Self::SIZE],
    ) -> Result<ProofEvaluations, Self::Error> {
        let mut buffer = &buf[..];
        let a_eval = BlsScalar::from_reader(&mut buffer)?;
        let b_eval = BlsScalar::from_reader(&mut buffer)?;
        let o_eval = BlsScalar::from_reader(&mut buffer)?;
        let d_eval = BlsScalar::from_reader(&mut buffer)?;
        let a_next_eval = BlsScalar::from_reader(&mut buffer)?;
        let b_next_eval = BlsScalar::from_reader(&mut buffer)?;
        let d_next_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_arith_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_c_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_l_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_r_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_1_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_2_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_3_eval = BlsScalar::from_reader(&mut buffer)?;
        let r_poly_eval = BlsScalar::from_reader(&mut buffer)?;
        let z_eval = BlsScalar::from_reader(&mut buffer)?;

        Ok(ProofEvaluations {
            a_eval,
            b_eval,
            o_eval,
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
            z_eval,
        })
    }
}

#[cfg(feature = "alloc")]

/// Compute the linearization polynomial.
// TODO: Improve the method signature
#[allow(clippy::type_complexity)]
pub(crate) fn compute(
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
    a_w_poly: &Polynomial,
    b_w_poly: &Polynomial,
    d_w_poly: &Polynomial,
    t_x_poly: &Polynomial,
    z_poly: &Polynomial,
    a_eval: &BlsScalar,
    b_eval: &BlsScalar,
    o_eval: &BlsScalar,
    d_eval: &BlsScalar,
    s_sigma_1_eval: &BlsScalar,
    s_sigma_2_eval: &BlsScalar,
    s_sigma_3_eval: &BlsScalar,
    z_eval: &BlsScalar,
) -> (Polynomial, Evaluations) {
    // Compute evaluations
    let t_eval = t_x_poly.evaluate(z_challenge);

    let q_arith_eval = prover_key.arithmetic.q_arith.0.evaluate(z_challenge);
    let q_c_eval = prover_key.logic.q_c.0.evaluate(z_challenge);
    let q_l_eval = prover_key.fixed_base.q_l.0.evaluate(z_challenge);
    let q_r_eval = prover_key.fixed_base.q_r.0.evaluate(z_challenge);

    let a_next_eval = a_w_poly.evaluate(&(z_challenge * domain.group_gen));
    let b_next_eval = b_w_poly.evaluate(&(z_challenge * domain.group_gen));
    let d_next_eval = d_w_poly.evaluate(&(z_challenge * domain.group_gen));

    let f_1 = compute_circuit_satisfiability(
        (
            range_separation_challenge,
            logic_separation_challenge,
            fixed_base_separation_challenge,
            var_base_separation_challenge,
        ),
        a_eval,
        b_eval,
        o_eval,
        d_eval,
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
        (&a_eval, &b_eval, &o_eval, &d_eval),
        (&s_sigma_1_eval, &s_sigma_2_eval, &s_sigma_3_eval),
        z_eval,
        z_poly,
    );

    let r_poly = &f_1 + &f_2;

    // Evaluate linearization polynomial at challenge `z`
    let r_poly_eval = r_poly.evaluate(z_challenge);

    (
        r_poly,
        Evaluations {
            proof: ProofEvaluations {
                a_eval: *a_eval,
                b_eval: *b_eval,
                o_eval: *o_eval,
                d_eval: *d_eval,
                a_next_eval,
                b_next_eval,
                d_next_eval,
                q_arith_eval,
                q_c_eval,
                q_l_eval,
                q_r_eval,
                s_sigma_1_eval: *s_sigma_1_eval,
                s_sigma_2_eval: *s_sigma_2_eval,
                s_sigma_3_eval: *s_sigma_3_eval,
                r_poly_eval,
                z_eval: *z_eval,
            },
            t_eval,
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
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    a_eval: &BlsScalar,
    b_eval: &BlsScalar,
    o_eval: &BlsScalar,
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
        o_eval,
        d_eval,
        q_arith_eval,
    );

    let b = prover_key.range.compute_linearization(
        range_separation_challenge,
        a_eval,
        b_eval,
        o_eval,
        d_eval,
        d_next_eval,
    );

    let c = prover_key.logic.compute_linearization(
        logic_separation_challenge,
        a_eval,
        a_next_eval,
        b_eval,
        b_next_eval,
        o_eval,
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
        o_eval,
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
        o_eval,
        d_eval,
        d_next_eval,
    );

    let mut linearization_poly = &a + &b;
    linearization_poly += &c;
    linearization_poly += &d;
    linearization_poly += &e;

    linearization_poly
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
