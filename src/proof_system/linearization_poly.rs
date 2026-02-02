// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
use crate::{
    fft::{EvaluationDomain, Polynomial},
    proof_system::{ProverKey, proof},
};

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Serialize,
    ser::{ScratchSpace, Serializer},
};

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
    pub(crate) c_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_w_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_w_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of
    // unity`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_w_eval: BlsScalar,
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

    // (Shifted) Evaluation of the permutation polynomial at `z * root of
    // unity`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) z_eval: BlsScalar,
}

// The struct ProofEvaluations has 15 BlsScalars
impl Serializable<{ 15 * BlsScalar::SIZE }> for ProofEvaluations {
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
        writer.write(&self.a_w_eval.to_bytes());
        writer.write(&self.b_w_eval.to_bytes());
        writer.write(&self.d_w_eval.to_bytes());
        writer.write(&self.q_arith_eval.to_bytes());
        writer.write(&self.q_c_eval.to_bytes());
        writer.write(&self.q_l_eval.to_bytes());
        writer.write(&self.q_r_eval.to_bytes());
        writer.write(&self.s_sigma_1_eval.to_bytes());
        writer.write(&self.s_sigma_2_eval.to_bytes());
        writer.write(&self.s_sigma_3_eval.to_bytes());
        writer.write(&self.z_eval.to_bytes());

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
        let a_w_eval = BlsScalar::from_reader(&mut buffer)?;
        let b_w_eval = BlsScalar::from_reader(&mut buffer)?;
        let d_w_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_arith_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_c_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_l_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_r_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_1_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_2_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_3_eval = BlsScalar::from_reader(&mut buffer)?;
        let z_eval = BlsScalar::from_reader(&mut buffer)?;

        Ok(ProofEvaluations {
            a_eval,
            b_eval,
            c_eval,
            d_eval,
            a_w_eval,
            b_w_eval,
            d_w_eval,
            q_arith_eval,
            q_c_eval,
            q_l_eval,
            q_r_eval,
            s_sigma_1_eval,
            s_sigma_2_eval,
            s_sigma_3_eval,
            z_eval,
        })
    }
}

/// Compute the linearization polynomial.
// TODO: Improve the method signature
#[cfg(feature = "alloc")]
#[allow(clippy::type_complexity)]
pub(crate) fn compute(
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
    z_poly: &Polynomial,
    evaluations: &ProofEvaluations,
    domain: &EvaluationDomain,
    t_low_poly: &Polynomial,
    t_mid_poly: &Polynomial,
    t_high_poly: &Polynomial,
    t_fourth_poly: &Polynomial,
    pub_inputs: &[BlsScalar],
) -> Polynomial {
    let f_1 = compute_circuit_satisfiability(
        (
            range_separation_challenge,
            logic_separation_challenge,
            fixed_base_separation_challenge,
            var_base_separation_challenge,
        ),
        evaluations,
        prover_key,
    );

    let pi_eval =
        proof::alloc::compute_barycentric_eval(pub_inputs, z_challenge, domain);

    let f_1 = &f_1 + &pi_eval;

    let f_2 = prover_key.permutation.compute_linearization(
        z_challenge,
        (alpha, beta, gamma),
        (
            &evaluations.a_eval,
            &evaluations.b_eval,
            &evaluations.c_eval,
            &evaluations.d_eval,
        ),
        (
            &evaluations.s_sigma_1_eval,
            &evaluations.s_sigma_2_eval,
            &evaluations.s_sigma_3_eval,
        ),
        &evaluations.z_eval,
        z_poly,
    );

    let domain_size = domain.size();

    let z_n = z_challenge.pow(&[domain_size as u64, 0, 0, 0]);
    let z_two_n = z_challenge.pow(&[2 * domain_size as u64, 0, 0, 0]);
    let z_three_n = z_challenge.pow(&[3 * domain_size as u64, 0, 0, 0]);

    let a = t_low_poly;
    let b = t_mid_poly * &z_n;
    let c = t_high_poly * &z_two_n;
    let d = t_fourth_poly * &z_three_n;
    let abc = &(a + &b) + &c;

    let quot = &abc + &d;

    let z_h_eval = -domain.evaluate_vanishing_polynomial(z_challenge);

    let quot = &quot * &z_h_eval;

    let f = &f_1 + &f_2;

    // r_poly
    &f + &quot
}

#[cfg(feature = "alloc")]
fn compute_circuit_satisfiability(
    (
        range_separation_challenge,
        logic_separation_challenge,
        fixed_base_separation_challenge,
        var_base_separation_challenge,
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    evaluations: &ProofEvaluations,
    prover_key: &ProverKey,
) -> Polynomial {
    let a = prover_key.arithmetic.compute_linearization(evaluations);

    let b = prover_key
        .range
        .compute_linearization(range_separation_challenge, evaluations);

    let c = prover_key
        .logic
        .compute_linearization(logic_separation_challenge, evaluations);

    let d = prover_key
        .fixed_base
        .compute_linearization(fixed_base_separation_challenge, evaluations);

    let e = prover_key
        .variable_base
        .compute_linearization(var_base_separation_challenge, evaluations);

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
