// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A Proof stores the commitments to all of the elements that
//! are needed to univocally identify a prove of some statement.
//!
//! This module contains the implementation of the `TurboComposer`s
//! `Proof` structure and it's methods.

use super::linearization_poly::ProofEvaluations;
use crate::commitment_scheme::Commitment;

use dusk_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use crate::util::check_field;
#[cfg(feature = "rkyv-impl")]
use bytecheck::{CheckBytes, StructCheckError};
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

/// A Proof is a composition of `Commitment`s to the Witness, Permutation,
/// Quotient, Shifted and Opening polynomials as well as the
/// `ProofEvaluations`.
///
/// It's main goal is to allow the `Verifier` to
/// formally verify that the secret witnesses used to generate the [`Proof`]
/// satisfy a circuit that both [`Prover`](super::Prover) and
/// [`Verifier`](super::Verifier) have in common succinctly and without any
/// capabilities of acquiring any kind of knowledge about the witness used to
/// construct the Proof.
#[derive(Debug, Eq, PartialEq, Clone, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace"))
)]
pub struct Proof {
    /// Commitment to the witness polynomial for the left wires.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_comm: Commitment,
    /// Commitment to the witness polynomial for the right wires.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_comm: Commitment,
    /// Commitment to the witness polynomial for the output wires.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) c_comm: Commitment,
    /// Commitment to the witness polynomial for the fourth wires.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_comm: Commitment,

    /// Commitment to the permutation polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) z_comm: Commitment,

    /// Commitment to the quotient polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_low_comm: Commitment,
    /// Commitment to the quotient polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_mid_comm: Commitment,
    /// Commitment to the quotient polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_high_comm: Commitment,
    /// Commitment to the quotient polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_4_comm: Commitment,

    /// Commitment to the opening polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) w_z_chall_comm: Commitment,
    /// Commitment to the shifted opening polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) w_z_chall_w_comm: Commitment,
    /// Subset of all of the evaluations added to the proof.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) evaluations: ProofEvaluations,
}

#[cfg(feature = "rkyv-impl")]
impl<C> CheckBytes<C> for ArchivedProof {
    type Error = StructCheckError;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        check_field(&(*value).a_comm, context, "a_comm")?;
        check_field(&(*value).b_comm, context, "b_comm")?;
        check_field(&(*value).c_comm, context, "c_comm")?;
        check_field(&(*value).d_comm, context, "d_comm")?;

        check_field(&(*value).z_comm, context, "z_comm")?;

        check_field(&(*value).t_low_comm, context, "t_low_comm")?;
        check_field(&(*value).t_mid_comm, context, "t_mid_comm")?;
        check_field(&(*value).t_high_comm, context, "t_high_comm")?;
        check_field(&(*value).t_4_comm, context, "t_4_comm")?;

        check_field(&(*value).w_z_chall_comm, context, "w_z_chall_comm")?;
        check_field(&(*value).w_z_chall_w_comm, context, "w_z_chall_w_comm")?;
        check_field(&(*value).evaluations, context, "evaluations")?;

        Ok(&*value)
    }
}

// The struct Proof has 11 commitments + 1 ProofEvaluations
impl Serializable<{ 11 * Commitment::SIZE + ProofEvaluations::SIZE }>
    for Proof
{
    type Error = dusk_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;

        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        writer.write(&self.a_comm.to_bytes());
        writer.write(&self.b_comm.to_bytes());
        writer.write(&self.c_comm.to_bytes());
        writer.write(&self.d_comm.to_bytes());
        writer.write(&self.z_comm.to_bytes());
        writer.write(&self.t_low_comm.to_bytes());
        writer.write(&self.t_mid_comm.to_bytes());
        writer.write(&self.t_high_comm.to_bytes());
        writer.write(&self.t_4_comm.to_bytes());
        writer.write(&self.w_z_chall_comm.to_bytes());
        writer.write(&self.w_z_chall_w_comm.to_bytes());
        writer.write(&self.evaluations.to_bytes());

        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut buffer = &buf[..];

        let a_comm = Commitment::from_reader(&mut buffer)?;
        let b_comm = Commitment::from_reader(&mut buffer)?;
        let c_comm = Commitment::from_reader(&mut buffer)?;
        let d_comm = Commitment::from_reader(&mut buffer)?;
        let z_comm = Commitment::from_reader(&mut buffer)?;
        let t_low_comm = Commitment::from_reader(&mut buffer)?;
        let t_mid_comm = Commitment::from_reader(&mut buffer)?;
        let t_high_comm = Commitment::from_reader(&mut buffer)?;
        let t_4_comm = Commitment::from_reader(&mut buffer)?;
        let w_z_chall_comm = Commitment::from_reader(&mut buffer)?;
        let w_z_chall_w_comm = Commitment::from_reader(&mut buffer)?;
        let evaluations = ProofEvaluations::from_reader(&mut buffer)?;

        Ok(Proof {
            a_comm,
            b_comm,
            c_comm,
            d_comm,
            z_comm,
            t_low_comm,
            t_mid_comm,
            t_high_comm,
            t_4_comm,
            w_z_chall_comm,
            w_z_chall_w_comm,
            evaluations,
        })
    }
}

#[cfg(feature = "alloc")]
pub(crate) mod alloc {
    use super::*;
    use crate::{
        commitment_scheme::{AggregateProof, OpeningKey},
        error::Error,
        fft::EvaluationDomain,
        proof_system::widget::VerifierKey,
        transcript::TranscriptProtocol,
        util::batch_inversion,
    };
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{
        multiscalar_mul::msm_variable_base, BlsScalar, G1Affine,
    };
    use merlin::Transcript;
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    impl Proof {
        /// Performs the verification of a [`Proof`] returning a boolean result.
        pub(crate) fn verify(
            &self,
            verifier_key: &VerifierKey,
            transcript: &mut Transcript,
            opening_key: &OpeningKey,
            pub_inputs: &[BlsScalar],
        ) -> Result<(), Error> {
            let domain = EvaluationDomain::new(verifier_key.n)?;

            // Subgroup checks are done when the proof is deserialized.

            // In order for the Verifier and Prover to have the same view in the
            // non-interactive setting Both parties must commit the same
            // elements into the transcript Below the verifier will simulate
            // an interaction with the prover by adding the same elements
            // that the prover added into the transcript, hence generating the
            // same challenges
            //
            // Add commitment to witness polynomials to transcript
            transcript.append_commitment(b"a_w", &self.a_comm);
            transcript.append_commitment(b"b_w", &self.b_comm);
            transcript.append_commitment(b"c_w", &self.c_comm);
            transcript.append_commitment(b"d_w", &self.d_comm);

            // Compute beta and gamma challenges
            let beta = transcript.challenge_scalar(b"beta");
            transcript.append_scalar(b"beta", &beta);
            let gamma = transcript.challenge_scalar(b"gamma");

            // Add commitment to permutation polynomial to transcript
            transcript.append_commitment(b"z", &self.z_comm);

            // Compute quotient challenge
            let alpha = transcript.challenge_scalar(b"alpha");
            let range_sep_challenge =
                transcript.challenge_scalar(b"range separation challenge");
            let logic_sep_challenge =
                transcript.challenge_scalar(b"logic separation challenge");
            let fixed_base_sep_challenge =
                transcript.challenge_scalar(b"fixed base separation challenge");
            let var_base_sep_challenge = transcript
                .challenge_scalar(b"variable base separation challenge");

            // Add commitment to quotient polynomial to transcript
            transcript.append_commitment(b"t_low", &self.t_low_comm);
            transcript.append_commitment(b"t_mid", &self.t_mid_comm);
            transcript.append_commitment(b"t_high", &self.t_high_comm);
            transcript.append_commitment(b"t_4", &self.t_4_comm);

            // Compute evaluation challenge z
            let z_challenge = transcript.challenge_scalar(b"z_challenge");

            // Compute zero polynomial evaluated at challenge `z`
            let z_h_eval = domain.evaluate_vanishing_polynomial(&z_challenge);

            // Compute first lagrange polynomial evaluated at challenge `z`
            let l1_eval = compute_first_lagrange_evaluation(
                &domain,
                &z_h_eval,
                &z_challenge,
            );

            // Compute quotient polynomial evaluated at challenge `z`
            let t_eval = self.compute_quotient_evaluation(
                &domain,
                pub_inputs,
                &alpha,
                &beta,
                &gamma,
                &z_challenge,
                &z_h_eval,
                &l1_eval,
                &self.evaluations.perm_eval,
            );

            // Compute commitment to quotient polynomial
            // This method is necessary as we pass the `un-splitted` variation
            // to our commitment scheme
            let t_comm =
                self.compute_quotient_commitment(&z_challenge, domain.size());

            // Add evaluations to transcript
            transcript.append_scalar(b"a_eval", &self.evaluations.a_eval);
            transcript.append_scalar(b"b_eval", &self.evaluations.b_eval);
            transcript.append_scalar(b"c_eval", &self.evaluations.c_eval);
            transcript.append_scalar(b"d_eval", &self.evaluations.d_eval);
            transcript
                .append_scalar(b"a_next_eval", &self.evaluations.a_next_eval);
            transcript
                .append_scalar(b"b_next_eval", &self.evaluations.b_next_eval);
            transcript
                .append_scalar(b"d_next_eval", &self.evaluations.d_next_eval);
            transcript.append_scalar(
                b"s_sigma_1_eval",
                &self.evaluations.s_sigma_1_eval,
            );
            transcript.append_scalar(
                b"s_sigma_2_eval",
                &self.evaluations.s_sigma_2_eval,
            );
            transcript.append_scalar(
                b"s_sigma_3_eval",
                &self.evaluations.s_sigma_3_eval,
            );
            transcript
                .append_scalar(b"q_arith_eval", &self.evaluations.q_arith_eval);
            transcript.append_scalar(b"q_c_eval", &self.evaluations.q_c_eval);
            transcript.append_scalar(b"q_l_eval", &self.evaluations.q_l_eval);
            transcript.append_scalar(b"q_r_eval", &self.evaluations.q_r_eval);
            transcript.append_scalar(b"perm_eval", &self.evaluations.perm_eval);
            transcript.append_scalar(b"t_eval", &t_eval);
            transcript.append_scalar(b"r_eval", &self.evaluations.r_poly_eval);

            // Compute linearization commitment
            let r_comm = self.compute_linearization_commitment(
                &alpha,
                &beta,
                &gamma,
                (
                    &range_sep_challenge,
                    &logic_sep_challenge,
                    &fixed_base_sep_challenge,
                    &var_base_sep_challenge,
                ),
                &z_challenge,
                l1_eval,
                verifier_key,
            );

            // Commitment Scheme
            // Now we delegate computation to the commitment scheme by batch
            // checking two proofs The `AggregateProof`, which is a
            // proof that all the necessary polynomials evaluated at
            // challenge `z` are correct and a `SingleProof` which
            // is proof that the permutation polynomial evaluated at the shifted
            // root of unity is correct

            // Compose the Aggregated Proof
            //
            let mut aggregate_proof =
                AggregateProof::with_witness(self.w_z_chall_comm);
            aggregate_proof.add_part((t_eval, t_comm));
            aggregate_proof.add_part((self.evaluations.r_poly_eval, r_comm));
            aggregate_proof.add_part((self.evaluations.a_eval, self.a_comm));
            aggregate_proof.add_part((self.evaluations.b_eval, self.b_comm));
            aggregate_proof.add_part((self.evaluations.c_eval, self.c_comm));
            aggregate_proof.add_part((self.evaluations.d_eval, self.d_comm));
            aggregate_proof.add_part((
                self.evaluations.s_sigma_1_eval,
                verifier_key.permutation.s_sigma_1,
            ));
            aggregate_proof.add_part((
                self.evaluations.s_sigma_2_eval,
                verifier_key.permutation.s_sigma_2,
            ));
            aggregate_proof.add_part((
                self.evaluations.s_sigma_3_eval,
                verifier_key.permutation.s_sigma_3,
            ));
            // Flatten proof with opening challenge
            let flattened_proof_a = aggregate_proof.flatten(transcript);

            // Compose the shifted aggregate proof
            let mut shifted_aggregate_proof =
                AggregateProof::with_witness(self.w_z_chall_w_comm);
            shifted_aggregate_proof
                .add_part((self.evaluations.perm_eval, self.z_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.a_next_eval, self.a_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.b_next_eval, self.b_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.d_next_eval, self.d_comm));

            let flattened_proof_b = shifted_aggregate_proof.flatten(transcript);
            // Add commitment to openings to transcript
            transcript.append_commitment(b"w_z", &self.w_z_chall_comm);
            transcript.append_commitment(b"w_z_w", &self.w_z_chall_w_comm);
            // Batch check
            if opening_key
                .batch_check(
                    &[z_challenge, (z_challenge * domain.group_gen)],
                    &[flattened_proof_a, flattened_proof_b],
                    transcript,
                )
                .is_err()
            {
                return Err(Error::ProofVerificationError);
            }

            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        fn compute_quotient_evaluation(
            &self,
            domain: &EvaluationDomain,
            pub_inputs: &[BlsScalar],
            alpha: &BlsScalar,
            beta: &BlsScalar,
            gamma: &BlsScalar,
            z_challenge: &BlsScalar,
            z_h_eval: &BlsScalar,
            l1_eval: &BlsScalar,
            z_hat_eval: &BlsScalar,
        ) -> BlsScalar {
            // Compute the public input polynomial evaluated at challenge `z`
            let pi_eval =
                compute_barycentric_eval(pub_inputs, z_challenge, domain);

            // Compute powers of alpha_0
            let alpha_sq = alpha.square();

            // r + PI(z)
            let a = self.evaluations.r_poly_eval + pi_eval;

            // a + beta * sigma_1 + gamma
            let beta_sig1 = beta * self.evaluations.s_sigma_1_eval;
            let b_0 = self.evaluations.a_eval + beta_sig1 + gamma;

            // b + beta * sigma_2 + gamma
            let beta_sig2 = beta * self.evaluations.s_sigma_2_eval;
            let b_1 = self.evaluations.b_eval + beta_sig2 + gamma;

            // c + beta * sigma_3 + gamma
            let beta_sig3 = beta * self.evaluations.s_sigma_3_eval;
            let b_2 = self.evaluations.c_eval + beta_sig3 + gamma;

            // ((d + gamma) * z_hat) * alpha_0
            let b_3 = (self.evaluations.d_eval + gamma) * z_hat_eval * alpha;

            let b = b_0 * b_1 * b_2 * b_3;

            // l_1(z) * alpha_0^2
            let c = l1_eval * alpha_sq;

            // Return t_eval
            (
                a - b - c
                //+ d
            ) * z_h_eval.invert().unwrap()
        }

        fn compute_quotient_commitment(
            &self,
            z_challenge: &BlsScalar,
            n: usize,
        ) -> Commitment {
            let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
            let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
            let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);
            let t_comm = self.t_low_comm.0
                + self.t_mid_comm.0 * z_n
                + self.t_high_comm.0 * z_two_n
                + self.t_4_comm.0 * z_three_n;
            Commitment::from(t_comm)
        }

        // Commitment to [r]_1
        #[allow(clippy::too_many_arguments)]
        fn compute_linearization_commitment(
            &self,
            alpha: &BlsScalar,
            beta: &BlsScalar,
            gamma: &BlsScalar,
            (
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
            ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
            z_challenge: &BlsScalar,
            l1_eval: BlsScalar,
            verifier_key: &VerifierKey,
        ) -> Commitment {
            let mut scalars: Vec<_> = Vec::with_capacity(6);
            let mut points: Vec<G1Affine> = Vec::with_capacity(6);

            verifier_key.arithmetic.compute_linearization_commitment(
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.range.compute_linearization_commitment(
                range_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.logic.compute_linearization_commitment(
                logic_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.fixed_base.compute_linearization_commitment(
                fixed_base_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.variable_base.compute_linearization_commitment(
                var_base_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.permutation.compute_linearization_commitment(
                &mut scalars,
                &mut points,
                &self.evaluations,
                z_challenge,
                (alpha, beta, gamma),
                &l1_eval,
                self.z_comm.0,
            );

            Commitment::from(msm_variable_base(&points, &scalars))
        }
    }

    fn compute_first_lagrange_evaluation(
        domain: &EvaluationDomain,
        z_h_eval: &BlsScalar,
        z_challenge: &BlsScalar,
    ) -> BlsScalar {
        let n_fr = BlsScalar::from(domain.size() as u64);
        let denom = n_fr * (z_challenge - BlsScalar::one());
        z_h_eval * denom.invert().unwrap()
    }

    fn compute_barycentric_eval(
        evaluations: &[BlsScalar],
        point: &BlsScalar,
        domain: &EvaluationDomain,
    ) -> BlsScalar {
        let numerator = (point.pow(&[domain.size() as u64, 0, 0, 0])
            - BlsScalar::one())
            * domain.size_inv;

        // Indices with non-zero evaluations
        #[cfg(not(feature = "std"))]
        let range = (0..evaluations.len()).into_iter();

        #[cfg(feature = "std")]
        let range = (0..evaluations.len()).into_par_iter();

        let non_zero_evaluations: Vec<usize> = range
            .filter(|&i| {
                let evaluation = &evaluations[i];
                evaluation != &BlsScalar::zero()
            })
            .collect();

        // Only compute the denominators with non-zero evaluations
        #[cfg(not(feature = "std"))]
        let range = (0..non_zero_evaluations.len()).into_iter();

        #[cfg(feature = "std")]
        let range = (0..non_zero_evaluations.len()).into_par_iter();

        let mut denominators: Vec<BlsScalar> = range
            .clone()
            .map(|i| {
                // index of non-zero evaluation
                let index = non_zero_evaluations[i];

                (domain.group_gen_inv.pow(&[index as u64, 0, 0, 0]) * point)
                    - BlsScalar::one()
            })
            .collect();
        batch_inversion(&mut denominators);

        let result: BlsScalar = range
            .map(|i| {
                let eval_index = non_zero_evaluations[i];
                let eval = evaluations[eval_index];

                denominators[i] * eval
            })
            .sum();

        result * numerator
    }
}

#[cfg(test)]
mod proof_tests {
    use super::*;
    use dusk_bls12_381::BlsScalar;
    use rand_core::OsRng;

    #[test]
    fn test_dusk_bytes_serde_proof() {
        let proof = Proof {
            a_comm: Commitment::default(),
            b_comm: Commitment::default(),
            c_comm: Commitment::default(),
            d_comm: Commitment::default(),
            z_comm: Commitment::default(),
            t_low_comm: Commitment::default(),
            t_mid_comm: Commitment::default(),
            t_high_comm: Commitment::default(),
            t_4_comm: Commitment::default(),
            w_z_chall_comm: Commitment::default(),
            w_z_chall_w_comm: Commitment::default(),
            evaluations: ProofEvaluations {
                a_eval: BlsScalar::random(&mut OsRng),
                b_eval: BlsScalar::random(&mut OsRng),
                c_eval: BlsScalar::random(&mut OsRng),
                d_eval: BlsScalar::random(&mut OsRng),
                a_next_eval: BlsScalar::random(&mut OsRng),
                b_next_eval: BlsScalar::random(&mut OsRng),
                d_next_eval: BlsScalar::random(&mut OsRng),
                q_arith_eval: BlsScalar::random(&mut OsRng),
                q_c_eval: BlsScalar::random(&mut OsRng),
                q_l_eval: BlsScalar::random(&mut OsRng),
                q_r_eval: BlsScalar::random(&mut OsRng),
                s_sigma_1_eval: BlsScalar::random(&mut OsRng),
                s_sigma_2_eval: BlsScalar::random(&mut OsRng),
                s_sigma_3_eval: BlsScalar::random(&mut OsRng),
                r_poly_eval: BlsScalar::random(&mut OsRng),
                perm_eval: BlsScalar::random(&mut OsRng),
            },
        };

        let proof_bytes = proof.to_bytes();
        let got_proof = Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(got_proof, proof);
    }
}
