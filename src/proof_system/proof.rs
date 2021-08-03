// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A Proof stores the commitments to all of the elements that
//! are needed to univocally identify a prove of some statement.
//!
//! This module contains the implementation of the `StandardComposer`s
//! `Proof` structure and it's methods.

use super::linearisation_poly::ProofEvaluations;
use crate::commitment_scheme::kzg10::Commitment;
use crate::error::Error;
use dusk_bytes::{DeserializableSlice, Serializable};

/// A Proof is a composition of `Commitment`s to the Witness, Permutation,
/// Quotient, Shifted and Opening polynomials as well as the
/// `ProofEvaluations`.
///
/// It's main goal is to allow the `Verifier` to
/// formally verify that the secret witnesses used to generate the [`Proof`]
/// satisfy a circuit that both [`Prover`](super::Prover) and
/// [`Verifier`](super::Verifier) have in common succintly and without any
/// capabilities of adquiring any kind of knowledge about the witness used to
/// construct the Proof.
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct Proof {
    /// Commitment to the witness polynomial for the left wires.
    pub(crate) a_comm: Commitment,
    /// Commitment to the witness polynomial for the right wires.
    pub(crate) b_comm: Commitment,
    /// Commitment to the witness polynomial for the output wires.
    pub(crate) c_comm: Commitment,
    /// Commitment to the witness polynomial for the fourth wires.
    pub(crate) d_comm: Commitment,

    /// Commitment to the lookup query polynomial.
    pub(crate) f_comm: Commitment,

    /// Commitment to first half of sorted polynomial
    pub(crate) h_1_comm: Commitment,

    /// Commitment to second half of sorted polynomial
    pub(crate) h_2_comm: Commitment,

    /// Commitment to the permutation polynomial.
    pub(crate) z_comm: Commitment,

    /// Commitment to the plookup permutation polynomial.
    pub(crate) p_comm: Commitment,

    /// Commitment to the quotient polynomial.
    pub(crate) t_1_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub(crate) t_2_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub(crate) t_3_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub(crate) t_4_comm: Commitment,

    /// Commitment to the opening polynomial.
    pub(crate) w_z_comm: Commitment,
    /// Commitment to the shifted opening polynomial.
    pub(crate) w_zw_comm: Commitment,
    /// Subset of all of the evaluations added to the proof.
    pub(crate) evaluations: ProofEvaluations,
}

impl Serializable<{ 15 * Commitment::SIZE + ProofEvaluations::SIZE }>
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
        writer.write(&self.f_comm.to_bytes());
        writer.write(&self.h_1_comm.to_bytes());
        writer.write(&self.h_2_comm.to_bytes());
        writer.write(&self.z_comm.to_bytes());
        writer.write(&self.p_comm.to_bytes());
        writer.write(&self.t_1_comm.to_bytes());
        writer.write(&self.t_2_comm.to_bytes());
        writer.write(&self.t_3_comm.to_bytes());
        writer.write(&self.t_4_comm.to_bytes());
        writer.write(&self.w_z_comm.to_bytes());
        writer.write(&self.w_zw_comm.to_bytes());
        writer.write(&self.evaluations.to_bytes());

        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut buffer = &buf[..];

        let a_comm = Commitment::from_reader(&mut buffer)?;
        let b_comm = Commitment::from_reader(&mut buffer)?;
        let c_comm = Commitment::from_reader(&mut buffer)?;
        let d_comm = Commitment::from_reader(&mut buffer)?;
        let f_comm = Commitment::from_reader(&mut buffer)?;
        let h_1_comm = Commitment::from_reader(&mut buffer)?;
        let h_2_comm = Commitment::from_reader(&mut buffer)?;
        let z_comm = Commitment::from_reader(&mut buffer)?;
        let p_comm = Commitment::from_reader(&mut buffer)?;
        let t_1_comm = Commitment::from_reader(&mut buffer)?;
        let t_2_comm = Commitment::from_reader(&mut buffer)?;
        let t_3_comm = Commitment::from_reader(&mut buffer)?;
        let t_4_comm = Commitment::from_reader(&mut buffer)?;
        let w_z_comm = Commitment::from_reader(&mut buffer)?;
        let w_zw_comm = Commitment::from_reader(&mut buffer)?;
        let evaluations = ProofEvaluations::from_reader(&mut buffer)?;

        Ok(Proof {
            a_comm,
            b_comm,
            c_comm,
            d_comm,
            f_comm,
            h_1_comm,
            h_2_comm,
            z_comm,
            p_comm,
            t_1_comm,
            t_2_comm,
            t_3_comm,
            t_4_comm,
            w_z_comm,
            w_zw_comm,
            evaluations,
        })
    }
}

#[cfg(feature = "alloc")]
pub(crate) mod alloc {
    use super::*;
    use crate::{
        commitment_scheme::kzg10::{AggregateProof, OpeningKey},
        fft::EvaluationDomain,
        proof_system::widget::VerifierKey,
        transcript::TranscriptProtocol,
        util::batch_inversion,
    };
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{
        multiscalar_mul::msm_variable_base, BlsScalar, G1Affine,
    };
    use merlin::Transcript;
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    impl Proof {
        /// Performs the verification of a `Proof` returning a boolean result.
        pub(crate) fn verify(
            &self,
            verifier_key: &VerifierKey,
            transcript: &mut Transcript,
            opening_key: &OpeningKey,
            pub_inputs: &[BlsScalar],
        ) -> Result<(), Error> {
            let domain = EvaluationDomain::new(verifier_key.n)?;

            // Subgroup checks are done when the proof is deserialised.

            // In order for the Verifier and Prover to have the same view in the
            // non-interactive setting Both parties must commit the
            // same elements into the transcript Below the verifier
            // will simulate an interaction with the prover by adding the same
            // elements that the prover added into the transcript,
            // hence generating the same challenges
            //
            // Add commitment to witness polynomials to transcript
            transcript.append_commitment(b"w_l", &self.a_comm);
            transcript.append_commitment(b"w_r", &self.b_comm);
            transcript.append_commitment(b"w_o", &self.c_comm);
            transcript.append_commitment(b"w_4", &self.d_comm);

            // Compute zeta compression challenge
            let zeta = transcript.challenge_scalar(b"zeta");

            // Add f_poly commitment to transcript
            transcript.append_commitment(b"f", &self.f_comm);

            // Compute beta and gamma challenges
            let beta = transcript.challenge_scalar(b"beta");
            transcript.append_scalar(b"beta", &beta);
            let gamma = transcript.challenge_scalar(b"gamma");

            // Compute delta and epsilon challenges
            let delta = transcript.challenge_scalar(b"delta");
            let epsilon = transcript.challenge_scalar(b"epsilon");

            // Add commitment to permutation polynomial to transcript
            transcript.append_commitment(b"z", &self.z_comm);

            // Compute evaluation challenge
            let z_challenge = transcript.challenge_scalar(b"z_challenge");

            // Add h polynomials to transcript
            transcript.append_commitment(b"h1", &self.h_1_comm);
            transcript.append_commitment(b"h2", &self.h_2_comm);

            // Add permutation polynomial commitment to transcript
            transcript.append_commitment(b"p", &self.p_comm);

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
            let lookup_sep_challenge =
                transcript.challenge_scalar(b"lookup challenge");

            // Add commitment to quotient polynomial to transcript
            transcript.append_commitment(b"t_1", &self.t_1_comm);
            transcript.append_commitment(b"t_2", &self.t_2_comm);
            transcript.append_commitment(b"t_3", &self.t_3_comm);
            transcript.append_commitment(b"t_4", &self.t_4_comm);

            // Compute zero polynomial evaluated at `z_challenge`
            let z_h_eval = domain.evaluate_vanishing_polynomial(&z_challenge);

            // Compute first lagrange polynomial evaluated at `z_challenge`
            let l1_eval = compute_first_lagrange_evaluation(
                &domain,
                &z_h_eval,
                &z_challenge,
            );

            let table_comm = Commitment(G1Affine::from(
                verifier_key.lookup.table_1.0
                    + verifier_key.lookup.table_2.0 * zeta
                    + verifier_key.lookup.table_3.0 * zeta * zeta
                    + verifier_key.lookup.table_4.0 * zeta * zeta * zeta,
            ));

            // Compute quotient polynomial evaluated at `z_challenge`
            let t_eval = self.compute_quotient_evaluation(
                &domain,
                pub_inputs,
                &alpha,
                &beta,
                &gamma,
                &delta,
                &epsilon,
                &z_challenge,
                &z_h_eval,
                &l1_eval,
                &self.evaluations.perm_eval,
                &lookup_sep_challenge,
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
                b"left_sig_eval",
                &self.evaluations.left_sigma_eval,
            );
            transcript.append_scalar(
                b"right_sig_eval",
                &self.evaluations.right_sigma_eval,
            );
            transcript.append_scalar(
                b"out_sig_eval",
                &self.evaluations.out_sigma_eval,
            );
            transcript
                .append_scalar(b"q_arith_eval", &self.evaluations.q_arith_eval);
            transcript.append_scalar(b"q_c_eval", &self.evaluations.q_c_eval);
            transcript.append_scalar(b"q_l_eval", &self.evaluations.q_l_eval);
            transcript.append_scalar(b"q_r_eval", &self.evaluations.q_r_eval);
            transcript.append_scalar(
                b"q_lookup_eval",
                &self.evaluations.q_lookup_eval,
            );
            transcript.append_scalar(b"perm_eval", &self.evaluations.perm_eval);
            transcript.append_scalar(
                b"lookup_perm_eval",
                &self.evaluations.lookup_perm_eval,
            );
            transcript.append_scalar(b"h_1_eval", &self.evaluations.h_1_eval);
            transcript.append_scalar(
                b"h_1_next_eval",
                &self.evaluations.h_1_next_eval,
            );
            transcript.append_scalar(b"h_2_eval", &self.evaluations.h_2_eval);
            transcript.append_scalar(b"t_eval", &t_eval);
            transcript
                .append_scalar(b"r_eval", &self.evaluations.lin_poly_eval);

            // Compute linearisation commitment
            let r_comm = self.compute_linearisation_commitment(
                &alpha,
                &beta,
                &gamma,
                &delta,
                &epsilon,
                &zeta,
                (
                    &range_sep_challenge,
                    &logic_sep_challenge,
                    &fixed_base_sep_challenge,
                    &var_base_sep_challenge,
                    &lookup_sep_challenge,
                ),
                &z_challenge,
                l1_eval,
                self.evaluations.table_eval,
                self.evaluations.table_next_eval,
                &verifier_key,
            );

            // Commitment Scheme
            // Now we delegate computation to the commitment scheme by batch
            // checking two proofs The `AggregateProof`, which is a
            // proof that all the necessary polynomials evaluated at
            // `z_challenge` are correct and a `SingleProof` which
            // is proof that the permutation polynomial evaluated at the shifted
            // root of unity is correct

            // Compose the Aggregated Proof
            //
            let mut aggregate_proof =
                AggregateProof::with_witness(self.w_z_comm);
            aggregate_proof.add_part((t_eval, t_comm));
            aggregate_proof.add_part((self.evaluations.lin_poly_eval, r_comm));
            aggregate_proof.add_part((self.evaluations.a_eval, self.a_comm));
            aggregate_proof.add_part((self.evaluations.b_eval, self.b_comm));
            aggregate_proof.add_part((self.evaluations.c_eval, self.c_comm));
            aggregate_proof.add_part((self.evaluations.d_eval, self.d_comm));
            aggregate_proof.add_part((
                self.evaluations.left_sigma_eval,
                verifier_key.permutation.left_sigma,
            ));
            aggregate_proof.add_part((
                self.evaluations.right_sigma_eval,
                verifier_key.permutation.right_sigma,
            ));
            aggregate_proof.add_part((
                self.evaluations.out_sigma_eval,
                verifier_key.permutation.out_sigma,
            ));
            aggregate_proof.add_part((self.evaluations.f_eval, self.f_comm));
            aggregate_proof
                .add_part((self.evaluations.h_1_eval, self.h_1_comm));
            aggregate_proof
                .add_part((self.evaluations.h_2_eval, self.h_2_comm));
            aggregate_proof.add_part((self.evaluations.table_eval, table_comm));
            // Flatten proof with opening challenge
            let flattened_proof_a = aggregate_proof.flatten(transcript);

            // Compose the shifted aggregate proof
            let mut shifted_aggregate_proof =
                AggregateProof::with_witness(self.w_zw_comm);
            shifted_aggregate_proof
                .add_part((self.evaluations.perm_eval, self.z_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.a_next_eval, self.a_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.b_next_eval, self.b_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.d_next_eval, self.d_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.h_1_next_eval, self.h_1_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.lookup_perm_eval, self.p_comm));
            shifted_aggregate_proof
                .add_part((self.evaluations.table_next_eval, table_comm));
            let flattened_proof_b = shifted_aggregate_proof.flatten(transcript);
            // Add commitment to openings to transcript
            transcript.append_commitment(b"w_z", &self.w_z_comm);
            transcript.append_commitment(b"w_z_w", &self.w_zw_comm);
            // Batch check
            if opening_key
                .batch_check(
                    &[z_challenge, (z_challenge * domain.group_gen)],
                    &[flattened_proof_a, flattened_proof_b],
                    transcript,
                )
                .is_err()
            {
                return Err(Error::ProofVerificationError.into());
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
            delta: &BlsScalar,
            epsilon: &BlsScalar,
            z_challenge: &BlsScalar,
            z_h_eval: &BlsScalar,
            l1_eval: &BlsScalar,
            z_hat_eval: &BlsScalar,
            lookup_sep_challenge: &BlsScalar,
        ) -> BlsScalar {
            // Compute the public input polynomial evaluated at `z_challenge`
            let pi_eval =
                compute_barycentric_eval(pub_inputs, z_challenge, domain);

            // Compute powers of alpha_0
            let alpha_sq = alpha.square();

            // Compute powers of alpha_1
            let l_sep_2 = lookup_sep_challenge.square();
            let l_sep_3 = lookup_sep_challenge * l_sep_2;

            // Compute common term
            let epsilon_one_plus_delta = epsilon * (BlsScalar::one() + delta);

            // r + PI(z)
            let a = self.evaluations.lin_poly_eval + pi_eval;

            // a + beta * sigma_1 + gamma
            let beta_sig1 = beta * self.evaluations.left_sigma_eval;
            let b_0 = self.evaluations.a_eval + beta_sig1 + gamma;

            // b+ beta * sigma_2 + gamma
            let beta_sig2 = beta * self.evaluations.right_sigma_eval;
            let b_1 = self.evaluations.b_eval + beta_sig2 + gamma;

            // c+ beta * sigma_3 + gamma
            let beta_sig3 = beta * self.evaluations.out_sigma_eval;
            let b_2 = self.evaluations.c_eval + beta_sig3 + gamma;

            // ((d + gamma) * z_hat) * alpha_0
            let b_3 = (self.evaluations.d_eval + gamma) * z_hat_eval * alpha;

            let b = b_0 * b_1 * b_2 * b_3;

            // l_1(z) * alpha_0^2
            let c = l1_eval * alpha_sq;

            // l_1(z) * alpha_1^2
            let e = l1_eval * l_sep_2;

            // p_eval * (epsilon( 1+ delta) + h_1_eval + delta *
            // h_2_eval)(epsilon( 1+ delta) + delta * h_1_next_eval) * alpha_1^3
            let f_0 = epsilon_one_plus_delta
                + self.evaluations.h_1_eval
                + (delta * self.evaluations.h_2_eval);
            let f_1 = epsilon_one_plus_delta
                + (delta * self.evaluations.h_1_next_eval);
            let f = self.evaluations.lookup_perm_eval * f_0 * f_1 * l_sep_3;

            // Return t_eval
            (a - b - c //+ d
                 - e - f)
                * z_h_eval.invert().unwrap()
        }

        fn compute_quotient_commitment(
            &self,
            z_challenge: &BlsScalar,
            n: usize,
        ) -> Commitment {
            let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
            let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
            let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);
            let t_comm = self.t_1_comm.0
                + self.t_2_comm.0 * z_n
                + self.t_3_comm.0 * z_two_n
                + self.t_4_comm.0 * z_three_n;
            Commitment::from(t_comm)
        }

        // Commitment to [r]_1
        #[allow(clippy::too_many_arguments)]
        fn compute_linearisation_commitment(
            &self,
            alpha: &BlsScalar,
            beta: &BlsScalar,
            gamma: &BlsScalar,
            delta: &BlsScalar,
            epsilon: &BlsScalar,
            zeta: &BlsScalar,
            (
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
                lookup_sep_challenge,
            ): (
                &BlsScalar,
                &BlsScalar,
                &BlsScalar,
                &BlsScalar,
                &BlsScalar,
            ),
            z_challenge: &BlsScalar,
            l1_eval: BlsScalar,
            t_eval: BlsScalar,
            t_next_eval: BlsScalar,
            verifier_key: &VerifierKey,
        ) -> Commitment {
            let mut scalars: Vec<_> = Vec::with_capacity(6);
            let mut points: Vec<G1Affine> = Vec::with_capacity(6);

            verifier_key.arithmetic.compute_linearisation_commitment(
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.range.compute_linearisation_commitment(
                &range_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.logic.compute_linearisation_commitment(
                &logic_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.fixed_base.compute_linearisation_commitment(
                &fixed_base_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.variable_base.compute_linearisation_commitment(
                &var_base_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.lookup.compute_linearisation_commitment(
                lookup_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
                (&delta, &epsilon),
                &zeta,
                &l1_eval,
                &t_eval,
                &t_next_eval,
                self.h_2_comm.0,
                self.p_comm.0,
            );

            verifier_key.permutation.compute_linearisation_commitment(
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
            f_comm: Commitment::default(),
            h_1_comm: Commitment::default(),
            h_2_comm: Commitment::default(),
            z_comm: Commitment::default(),
            p_comm: Commitment::default(),
            t_1_comm: Commitment::default(),
            t_2_comm: Commitment::default(),
            t_3_comm: Commitment::default(),
            t_4_comm: Commitment::default(),
            w_z_comm: Commitment::default(),
            w_zw_comm: Commitment::default(),
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
                q_lookup_eval: BlsScalar::random(&mut OsRng),
                left_sigma_eval: BlsScalar::random(&mut OsRng),
                right_sigma_eval: BlsScalar::random(&mut OsRng),
                out_sigma_eval: BlsScalar::random(&mut OsRng),
                lin_poly_eval: BlsScalar::random(&mut OsRng),
                perm_eval: BlsScalar::random(&mut OsRng),
                lookup_perm_eval: BlsScalar::random(&mut OsRng),
                h_1_eval: BlsScalar::random(&mut OsRng),
                h_1_next_eval: BlsScalar::random(&mut OsRng),
                h_2_eval: BlsScalar::random(&mut OsRng),
                f_eval: BlsScalar::random(&mut OsRng),
                table_eval: BlsScalar::random(&mut OsRng),
                table_next_eval: BlsScalar::random(&mut OsRng),
            },
        };

        let proof_bytes = proof.to_bytes();
        let got_proof = Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(got_proof, proof);
    }
}
