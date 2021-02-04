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
use super::lookup_lineariser::PlookupProofEvaluations;
use super::proof_system_errors::ProofErrors;
use crate::commitment_scheme::kzg10::{AggregateProof, Commitment, OpeningKey};
use crate::fft::{EvaluationDomain, Polynomial};
use crate::plookup::{MultiSet, PreprocessedTable4Arity};
use crate::proof_system::widget::{PlookupVerifierKey, VerifierKey};
use crate::transcript::TranscriptProtocol;
use anyhow::{Error, Result};
use dusk_bls12_381::{multiscalar_mul::msm_variable_base, BlsScalar, G1Affine};
use dusk_bytes::Serializable;
use merlin::Transcript;
use serde::de::Visitor;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "canon")]
use canonical::{Canon, InvalidEncoding, Sink, Source, Store};

/// Byte-size of a serialised `Proof`.
pub const PROOF_SIZE: usize = Proof::serialised_size();

/// A Proof is a composition of `Commitments` to the witness, permutation,
/// quotient, shifted and opening polynomials as well as the
/// `ProofEvaluations`.
///
/// It's main goal is to have a `verify()` method attached which contains the
/// logic of the operations that the `Verifier` will need to do in order to
/// formally verify the `Proof`.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Proof {
    /// Commitment to the witness polynomial for the left wires.
    pub a_comm: Commitment,
    /// Commitment to the witness polynomial for the right wires.
    pub b_comm: Commitment,
    /// Commitment to the witness polynomial for the output wires.
    pub c_comm: Commitment,
    /// Commitment to the witness polynomial for the fourth wires.
    pub d_comm: Commitment,

    /// Commitment to the permutation polynomial.
    pub z_comm: Commitment,

    /// Commitment to the quotient polynomial.
    pub t_1_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_2_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_3_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_4_comm: Commitment,

    /// Commitment to the opening polynomial.
    pub w_z_comm: Commitment,
    /// Commitment to the shifted opening polynomial.
    pub w_zw_comm: Commitment,
    /// Subset of all of the evaluations added to the proof.
    pub evaluations: ProofEvaluations,
}

impl_serde!(Proof);

/// A plookup proof contains all of the fields of a plonk proof
/// and then some additionally derived fields
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PlookupProof {
    /// Commitment to the witness polynomial for the left wires.
    pub a_comm: Commitment,
    /// Commitment to the witness polynomial for the right wires.
    pub b_comm: Commitment,
    /// Commitment to the witness polynomial for the output wires.
    pub c_comm: Commitment,
    /// Commitment to the witness polynomial for the fourth wires.
    pub d_comm: Commitment,

    /// Commitment to the lookup query polynomial.
    pub f_comm: Commitment,

    /// Commitment to first half of sorted polynomial
    pub h_1_comm: Commitment,

    /// Commitment to second half of sorted polynomial
    pub h_2_comm: Commitment,

    /// Commitment to the permutation polynomial.
    pub z_comm: Commitment,

    /// Commitment to the plookup permutation polynomial.
    pub p_comm: Commitment,

    /// Commitment to the quotient polynomial.
    pub t_1_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_2_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_3_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_4_comm: Commitment,

    /// Commitment to the opening polynomial.
    pub w_z_comm: Commitment,
    /// Commitment to the shifted opening polynomial.
    pub w_zw_comm: Commitment,

    /// Subset of all of the evaluations added to the proof.
    pub evaluations: PlookupProofEvaluations,
}

#[cfg(feature = "canon")]
impl<S: Store> Canon<S> for Proof {
    fn write(&self, sink: &mut impl Sink<S>) -> Result<(), S::Error> {
        sink.copy_bytes(&self.to_bytes());
        Ok(())
    }

    fn read(source: &mut impl Source<S>) -> Result<Self, S::Error> {
        let mut bytes = [0u8; PROOF_SIZE];
        bytes.copy_from_slice(source.read_bytes(PROOF_SIZE));
        match Proof::from_bytes(&bytes) {
            Ok(proof) => Ok(proof),
            _ => Err(InvalidEncoding.into()),
        }
    }

    fn encoded_len(&self) -> usize {
        PROOF_SIZE
    }
}

impl Proof {
    /// Serialises a Proof struct
    pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
        let mut bytes = [0u8; PROOF_SIZE];

        bytes[0..48].copy_from_slice(&self.a_comm.0.to_bytes()[..]);
        bytes[48..96].copy_from_slice(&self.b_comm.0.to_bytes()[..]);
        bytes[96..144].copy_from_slice(&self.c_comm.0.to_bytes()[..]);
        bytes[144..192].copy_from_slice(&self.d_comm.0.to_bytes()[..]);
        bytes[192..240].copy_from_slice(&self.z_comm.0.to_bytes()[..]);
        bytes[240..288].copy_from_slice(&self.t_1_comm.0.to_bytes()[..]);
        bytes[288..336].copy_from_slice(&self.t_2_comm.0.to_bytes()[..]);
        bytes[336..384].copy_from_slice(&self.t_3_comm.0.to_bytes()[..]);
        bytes[384..432].copy_from_slice(&self.t_4_comm.0.to_bytes()[..]);
        bytes[432..480].copy_from_slice(&self.w_z_comm.0.to_bytes()[..]);
        bytes[480..528].copy_from_slice(&self.w_zw_comm.0.to_bytes()[..]);
        bytes[528..PROOF_SIZE].copy_from_slice(&self.evaluations.to_bytes()[..]);

        bytes
    }

    /// Deserialises a Proof struct
    pub fn from_bytes(bytes: &[u8]) -> Result<Proof, Error> {
        use crate::serialisation::read_commitment;

        let (a_comm, rest) = read_commitment(bytes)?;
        let (b_comm, rest) = read_commitment(rest)?;
        let (c_comm, rest) = read_commitment(rest)?;
        let (d_comm, rest) = read_commitment(rest)?;
        let (z_comm, rest) = read_commitment(rest)?;
        let (t_1_comm, rest) = read_commitment(rest)?;
        let (t_2_comm, rest) = read_commitment(rest)?;
        let (t_3_comm, rest) = read_commitment(rest)?;
        let (t_4_comm, rest) = read_commitment(rest)?;
        let (w_z_comm, rest) = read_commitment(rest)?;
        let (w_zw_comm, rest) = read_commitment(rest)?;

        let evaluations = ProofEvaluations::from_bytes(rest);

        let proof = Proof {
            a_comm,
            b_comm,
            c_comm,
            d_comm,
            z_comm,
            t_1_comm,
            t_2_comm,
            t_3_comm,
            t_4_comm,
            w_z_comm,
            w_zw_comm,
            evaluations: evaluations?,
        };
        Ok(proof)
    }

    /// Returns the serialised size of a [`Proof`] object.
    pub const fn serialised_size() -> usize {
        const NUM_COMMITMENTS: usize = 11;
        const COMMITMENT_SIZE: usize = 48;
        (NUM_COMMITMENTS * COMMITMENT_SIZE) + ProofEvaluations::serialised_size()
    }

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

        // In order for the Verifier and Prover to have the same view in the non-interactive setting
        // Both parties must commit the same elements into the transcript
        // Below the verifier will simulate an interaction with the prover by adding the same elements
        // that the prover added into the transcript, hence generating the same challenges
        //
        // Add commitment to witness polynomials to transcript
        transcript.append_commitment(b"w_l", &self.a_comm);
        transcript.append_commitment(b"w_r", &self.b_comm);
        transcript.append_commitment(b"w_o", &self.c_comm);
        transcript.append_commitment(b"w_4", &self.d_comm);

        // Compute beta and gamma challenges
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");
        // Add commitment to permutation polynomial to transcript
        transcript.append_commitment(b"z", &self.z_comm);

        // Compute quotient challenge
        let alpha = transcript.challenge_scalar(b"alpha");
        let range_sep_challenge = transcript.challenge_scalar(b"range separation challenge");
        let logic_sep_challenge = transcript.challenge_scalar(b"logic separation challenge");
        let fixed_base_sep_challenge =
            transcript.challenge_scalar(b"fixed base separation challenge");
        let var_base_sep_challenge =
            transcript.challenge_scalar(b"variable base separation challenge");

        // Add commitment to quotient polynomial to transcript
        transcript.append_commitment(b"t_1", &self.t_1_comm);
        transcript.append_commitment(b"t_2", &self.t_2_comm);
        transcript.append_commitment(b"t_3", &self.t_3_comm);
        transcript.append_commitment(b"t_4", &self.t_4_comm);

        // Compute evaluation challenge
        let z_challenge = transcript.challenge_scalar(b"z");

        // Compute zero polynomial evaluated at `z_challenge`
        let z_h_eval = domain.evaluate_vanishing_polynomial(&z_challenge);

        // Compute first lagrange polynomial evaluated at `z_challenge`
        let l1_eval = compute_first_lagrange_evaluation(&domain, &z_h_eval, &z_challenge);

        // Compute quotient polynomial evaluated at `z_challenge`
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
        // This method is necessary as we pass the `un-splitted` variation to our commitment scheme
        let t_comm = self.compute_quotient_commitment(&z_challenge, domain.size());

        // Add evaluations to transcript
        transcript.append_scalar(b"a_eval", &self.evaluations.a_eval);
        transcript.append_scalar(b"b_eval", &self.evaluations.b_eval);
        transcript.append_scalar(b"c_eval", &self.evaluations.c_eval);
        transcript.append_scalar(b"d_eval", &self.evaluations.d_eval);
        transcript.append_scalar(b"a_next_eval", &self.evaluations.a_next_eval);
        transcript.append_scalar(b"b_next_eval", &self.evaluations.b_next_eval);
        transcript.append_scalar(b"d_next_eval", &self.evaluations.d_next_eval);
        transcript.append_scalar(b"left_sig_eval", &self.evaluations.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &self.evaluations.right_sigma_eval);
        transcript.append_scalar(b"out_sig_eval", &self.evaluations.out_sigma_eval);
        transcript.append_scalar(b"q_arith_eval", &self.evaluations.q_arith_eval);
        transcript.append_scalar(b"q_c_eval", &self.evaluations.q_c_eval);
        transcript.append_scalar(b"q_l_eval", &self.evaluations.q_l_eval);
        transcript.append_scalar(b"q_r_eval", &self.evaluations.q_r_eval);
        transcript.append_scalar(b"perm_eval", &self.evaluations.perm_eval);
        transcript.append_scalar(b"t_eval", &t_eval);
        transcript.append_scalar(b"r_eval", &self.evaluations.lin_poly_eval);

        // Compute linearisation commitment
        let r_comm = self.compute_linearisation_commitment(
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
            &verifier_key,
        );

        // Commitment Scheme
        // Now we delegate computation to the commitment scheme by batch checking two proofs
        // The `AggregateProof`, which is a proof that all the necessary polynomials evaluated at `z_challenge` are correct
        // and a `SingleProof` which is proof that the permutation polynomial evaluated at the shifted root of unity is correct

        // Compose the Aggregated Proof
        //
        let mut aggregate_proof = AggregateProof::with_witness(self.w_z_comm);
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
        // Flatten proof with opening challenge
        let flattened_proof_a = aggregate_proof.flatten(transcript);

        // Compose the shifted aggregate proof
        let mut shifted_aggregate_proof = AggregateProof::with_witness(self.w_zw_comm);
        shifted_aggregate_proof.add_part((self.evaluations.perm_eval, self.z_comm));
        shifted_aggregate_proof.add_part((self.evaluations.a_next_eval, self.a_comm));
        shifted_aggregate_proof.add_part((self.evaluations.b_next_eval, self.b_comm));
        shifted_aggregate_proof.add_part((self.evaluations.d_next_eval, self.d_comm));
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
            return Err(ProofErrors::ProofVerificationError.into());
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
        // Compute the public input polynomial evaluated at `z_challenge`
        let pi_eval = compute_barycentric_eval(pub_inputs, z_challenge, domain);

        let alpha_sq = alpha.square();
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

        // ((d + gamma) * z_hat) * alpha
        let b_3 = (self.evaluations.d_eval + gamma) * z_hat_eval * alpha;

        let b = b_0 * b_1 * b_2 * b_3;

        // l_1(z) * alpha^2
        let c = l1_eval * alpha_sq;

        // Return t_eval
        (a - b - c) * z_h_eval.invert().unwrap()
    }

    fn compute_quotient_commitment(&self, z_challenge: &BlsScalar, n: usize) -> Commitment {
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
        let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);
        let t_comm = self.t_1_comm.0
            + self.t_2_comm.0 * z_n
            + self.t_3_comm.0 * z_two_n
            + self.t_4_comm.0 * z_three_n;
        Commitment::from_projective(t_comm)
    }

    // Commitment to [r]_1
    #[allow(clippy::too_many_arguments)]
    fn compute_linearisation_commitment(
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

        verifier_key.permutation.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
            z_challenge,
            (alpha, beta, gamma),
            &l1_eval,
            self.z_comm.0,
        );

        Commitment::from_projective(msm_variable_base(&points, &scalars))
    }
}

impl PlookupProof {
    /// Serialises a Proof struct
    // pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
    //     let mut bytes = [0u8; PROOF_SIZE];
    //     bytes[0..48].copy_from_slice(&self.a_comm.0.to_compressed()[..]);
    //     bytes[48..96].copy_from_slice(&self.b_comm.0.to_compressed()[..]);
    //     bytes[96..144].copy_from_slice(&self.c_comm.0.to_compressed()[..]);
    //     bytes[144..192].copy_from_slice(&self.d_comm.0.to_compressed()[..]);
    //     bytes[192..240].copy_from_slice(&self.z_comm.0.to_compressed()[..]);
    //     bytes[240..288].copy_from_slice(&self.t_1_comm.0.to_compressed()[..]);
    //     bytes[288..336].copy_from_slice(&self.t_2_comm.0.to_compressed()[..]);
    //     bytes[336..384].copy_from_slice(&self.t_3_comm.0.to_compressed()[..]);
    //     bytes[384..432].copy_from_slice(&self.t_4_comm.0.to_compressed()[..]);
    //     bytes[432..480].copy_from_slice(&self.w_z_comm.0.to_compressed()[..]);
    //     bytes[480..528].copy_from_slice(&self.w_zw_comm.0.to_compressed()[..]);
    //     bytes[528..PROOF_SIZE].copy_from_slice(&self.evaluations.to_bytes()[..]);

    //     bytes
    // }

    /// Deserialises a Proof struct
    pub fn from_bytes(bytes: &[u8]) -> Result<PlookupProof, Error> {
        use crate::serialisation::read_commitment;

        let (a_comm, rest) = read_commitment(bytes)?;
        let (b_comm, rest) = read_commitment(rest)?;
        let (c_comm, rest) = read_commitment(rest)?;
        let (d_comm, rest) = read_commitment(rest)?;
        let (f_comm, rest) = read_commitment(rest)?;
        let (h_1_comm, rest) = read_commitment(rest)?;
        let (h_2_comm, rest) = read_commitment(rest)?;
        let (z_comm, rest) = read_commitment(rest)?;
        let (p_comm, rest) = read_commitment(rest)?;
        let (t_1_comm, rest) = read_commitment(rest)?;
        let (t_2_comm, rest) = read_commitment(rest)?;
        let (t_3_comm, rest) = read_commitment(rest)?;
        let (t_4_comm, rest) = read_commitment(rest)?;
        let (w_z_comm, rest) = read_commitment(rest)?;
        let (w_zw_comm, rest) = read_commitment(rest)?;

        let evaluations = PlookupProofEvaluations::from_bytes(rest);

        let proof = PlookupProof {
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
            evaluations: evaluations?,
        };
        Ok(proof)
    }

    /// Returns the serialised size of a [`Proof`] object.
    pub const fn serialised_size() -> usize {
        const NUM_COMMITMENTS: usize = 11;
        const COMMITMENT_SIZE: usize = 48;
        (NUM_COMMITMENTS * COMMITMENT_SIZE) + ProofEvaluations::serialised_size()
    }

    /// Performs the verification of a `Proof` returning a boolean result.
    pub(crate) fn verify(
        &self,
        verifier_key: &PlookupVerifierKey,
        transcript: &mut Transcript,
        opening_key: &OpeningKey,
        lookup_table: &PreprocessedTable4Arity,
        pub_inputs: &[BlsScalar],
    ) -> Result<(), Error> {
        let domain = EvaluationDomain::new(verifier_key.n)?;

        // Subgroup checks are done when the proof is deserialised.

        // In order for the Verifier and Prover to have the same view in the non-interactive setting
        // Both parties must commit the same elements into the transcript
        // Below the verifier will simulate an interaction with the prover by adding the same elements
        // that the prover added into the transcript, hence generating the same challenges
        //
        // Add commitment to witness polynomials to transcript
        transcript.append_commitment(b"w_l", &self.a_comm);
        transcript.append_commitment(b"w_r", &self.b_comm);
        transcript.append_commitment(b"w_o", &self.c_comm);
        transcript.append_commitment(b"w_4", &self.d_comm);

        // Compute beta and gamma challenges
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");
        // Add commitment to permutation polynomial to transcript
        transcript.append_commitment(b"z", &self.z_comm);

        // Compute delta and epsilon challenges
        let delta = transcript.challenge_scalar(b"delta");
        let epsilon = transcript.challenge_scalar(b"epsilon");

        // Compute zeta compression challenge
        let zeta = transcript.challenge_scalar(b"zeta");

        // Compute quotient challenge
        let alpha = transcript.challenge_scalar(b"alpha");
        let range_sep_challenge = transcript.challenge_scalar(b"range separation challenge");
        let logic_sep_challenge = transcript.challenge_scalar(b"logic separation challenge");
        let fixed_base_sep_challenge =
            transcript.challenge_scalar(b"fixed base separation challenge");
        let var_base_sep_challenge =
            transcript.challenge_scalar(b"variable base separation challenge");
        let lookup_sep_challenge = transcript.challenge_scalar(b"lookup challenge");

        // Add commitment to quotient polynomial to transcript
        transcript.append_commitment(b"t_1", &self.t_1_comm);
        transcript.append_commitment(b"t_2", &self.t_2_comm);
        transcript.append_commitment(b"t_3", &self.t_3_comm);
        transcript.append_commitment(b"t_4", &self.t_4_comm);

        // Compute evaluation challenge
        let z_challenge = transcript.challenge_scalar(b"z");

        // Compute zero polynomial evaluated at `z_challenge`
        let z_h_eval = domain.evaluate_vanishing_polynomial(&z_challenge);

        // Compute first lagrange polynomial evaluated at `z_challenge`
        let l1_eval = compute_first_lagrange_evaluation(&domain, &z_h_eval, &z_challenge);

        // Compute n'th Lagrange poly evaluated at `z_challenge`
        let ln_eval = compute_nth_lagrange_evaluation(&domain, &z_h_eval, &z_challenge);

        // Compress table into vector of single elements
        let compressed_t = MultiSet::compress_four_arity(
            [
                &lookup_table.t_1.0,
                &lookup_table.t_2.0,
                &lookup_table.t_3.0,
                &lookup_table.t_4.0,
            ],
            zeta,
        );

        // Compute table poly
        let t = Polynomial::from_coefficients_vec(domain.ifft(&compressed_t.0.as_slice()));

        let table_eval = t.evaluate(&z_challenge);
        let table_next_eval = t.evaluate(&(z_challenge * domain.group_gen));

        // Compute quotient polynomial evaluated at `z_challenge`
        let t_eval = self.compute_quotient_evaluation(
            &domain,
            pub_inputs,
            &alpha,
            &beta,
            &gamma,
            &delta,
            &epsilon,
            &zeta,
            &z_challenge,
            &z_h_eval,
            &l1_eval,
            &ln_eval,
            &self.evaluations.perm_eval,
        );

        // Compute commitment to quotient polynomial
        // This method is necessary as we pass the `un-splitted` variation to our commitment scheme
        let t_comm = self.compute_quotient_commitment(&z_challenge, domain.size());

        // Add evaluations to transcript
        transcript.append_scalar(b"a_eval", &self.evaluations.a_eval);
        transcript.append_scalar(b"b_eval", &self.evaluations.b_eval);
        transcript.append_scalar(b"c_eval", &self.evaluations.c_eval);
        transcript.append_scalar(b"d_eval", &self.evaluations.d_eval);
        transcript.append_scalar(b"a_next_eval", &self.evaluations.a_next_eval);
        transcript.append_scalar(b"b_next_eval", &self.evaluations.b_next_eval);
        transcript.append_scalar(b"d_next_eval", &self.evaluations.d_next_eval);
        transcript.append_scalar(b"left_sig_eval", &self.evaluations.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &self.evaluations.right_sigma_eval);
        transcript.append_scalar(b"out_sig_eval", &self.evaluations.out_sigma_eval);
        transcript.append_scalar(b"q_arith_eval", &self.evaluations.q_arith_eval);
        transcript.append_scalar(b"q_c_eval", &self.evaluations.q_c_eval);
        transcript.append_scalar(b"q_l_eval", &self.evaluations.q_l_eval);
        transcript.append_scalar(b"q_r_eval", &self.evaluations.q_r_eval);
        transcript.append_scalar(b"q_lookup_eval", &self.evaluations.q_lookup_eval);
        transcript.append_scalar(b"perm_eval", &self.evaluations.perm_eval);
        transcript.append_scalar(b"t_eval", &t_eval);
        transcript.append_scalar(b"r_eval", &self.evaluations.lin_poly_eval);

        // Compute linearisation commitment
        let r_comm = self.compute_linearisation_commitment(
            &alpha,
            &beta,
            &gamma,
            &delta,
            &epsilon,
            (
                &range_sep_challenge,
                &logic_sep_challenge,
                &fixed_base_sep_challenge,
                &var_base_sep_challenge,
            ),
            &z_challenge,
            l1_eval,
            ln_eval,
            table_eval,
            table_next_eval,
            &verifier_key,
        );

        // Commitment Scheme
        // Now we delegate computation to the commitment scheme by batch checking two proofs
        // The `AggregateProof`, which is a proof that all the necessary polynomials evaluated at `z_challenge` are correct
        // and a `SingleProof` which is proof that the permutation polynomial evaluated at the shifted root of unity is correct

        // Compose the Aggregated Proof
        //
        let mut aggregate_proof = AggregateProof::with_witness(self.w_z_comm);
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
        aggregate_proof.add_part((self.evaluations.h_1_eval, self.h_1_comm));
        // Flatten proof with opening challenge
        let flattened_proof_a = aggregate_proof.flatten(transcript);

        // Compose the shifted aggregate proof
        let mut shifted_aggregate_proof = AggregateProof::with_witness(self.w_zw_comm);
        shifted_aggregate_proof.add_part((self.evaluations.perm_eval, self.z_comm));
        shifted_aggregate_proof.add_part((self.evaluations.a_next_eval, self.a_comm));
        shifted_aggregate_proof.add_part((self.evaluations.b_next_eval, self.b_comm));
        shifted_aggregate_proof.add_part((self.evaluations.d_next_eval, self.d_comm));
        shifted_aggregate_proof.add_part((self.evaluations.h_1_next_eval, self.h_1_comm));
        shifted_aggregate_proof.add_part((self.evaluations.h_2_next_eval, self.h_2_comm));
        shifted_aggregate_proof.add_part((self.evaluations.lookup_perm_eval, self.p_comm));
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
            return Err(ProofErrors::ProofVerificationError.into());
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
        zeta: &BlsScalar,
        z_challenge: &BlsScalar,
        z_h_eval: &BlsScalar,
        l1_eval: &BlsScalar,
        ln_eval: &BlsScalar,
        z_hat_eval: &BlsScalar,
    ) -> BlsScalar {
        // Compute the public input polynomial evaluated at `z_challenge`
        let pi_eval = compute_barycentric_eval(pub_inputs, z_challenge, domain);

        // Compute powers of alpha
        let alpha_sq = alpha.square();
        let alpha_cu = alpha_sq * alpha;
        let alpha_4 = alpha_cu * alpha;
        let alpha_5 = alpha_4 * alpha;
        let alpha_6 = alpha_5 * alpha;
        let alpha_7 = alpha_6 * alpha;

        // Compute power of zeta
        let zeta_sq = zeta.square();

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

        // ((d + gamma) * z_hat) * alpha
        let b_3 = (self.evaluations.d_eval + gamma) * z_hat_eval * alpha;

        let b = b_0 * b_1 * b_2 * b_3;

        // l_1(z) * alpha^2
        let c = l1_eval * alpha_sq;

        // q_lookup(z) * (a + b*zeta + c*zeta^2) * alpha^3
        let d_0 = self.evaluations.a_eval
            + (self.evaluations.b_eval * zeta)
            + (self.evaluations.c_eval * zeta_sq);
        let d = self.evaluations.q_lookup_eval * d_0 * alpha_cu;

        // l_1(z) * alpha^4
        let e = l1_eval * alpha_4;

        // (z - 1) * p_eval * (epsilon( 1+ delta) + h_1_eval +(delta * h_1_next_eval)(epsilon( 1+ delta) + delta * h_2_next_eval) * alpha^5
        let f_0 = z_challenge - BlsScalar::one();
        let f_1 = epsilon_one_plus_delta
            + self.evaluations.h_1_eval
            + (delta * self.evaluations.h_1_eval);
        let f_2 = epsilon_one_plus_delta + (delta * self.evaluations.h_2_next_eval);
        let f = f_0 * self.evaluations.lookup_perm_eval * f_1 * f_2 * alpha_5;

        // l_n(z) * h_2_next_eval * alpha_5
        let g = ln_eval * self.evaluations.h_2_next_eval * alpha_5;

        // l_n(z) * alpha^7
        let h = ln_eval * alpha_7;

        // Return t_eval
        (a - b - c + d - e - f - g - h) * z_h_eval.invert().unwrap()
    }

    fn compute_quotient_commitment(&self, z_challenge: &BlsScalar, n: usize) -> Commitment {
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
        let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);
        let t_comm = self.t_1_comm.0
            + self.t_2_comm.0 * z_n
            + self.t_3_comm.0 * z_two_n
            + self.t_4_comm.0 * z_three_n;
        Commitment::from_projective(t_comm)
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
        (
            range_sep_challenge,
            logic_sep_challenge,
            fixed_base_sep_challenge,
            var_base_sep_challenge,
        ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
        z_challenge: &BlsScalar,
        l1_eval: BlsScalar,
        ln_eval: BlsScalar,
        t_eval: BlsScalar,
        t_next_eval: BlsScalar,
        verifier_key: &PlookupVerifierKey,
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
            &mut scalars,
            &mut points,
            &self.evaluations,
        );

        verifier_key.permutation.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
            z_challenge,
            (alpha, beta, gamma, delta, epsilon),
            &l1_eval,
            &ln_eval,
            &t_eval,
            &t_next_eval,
            self.z_comm.0,
            self.h_1_comm.0,
            self.h_2_comm.0,
            self.p_comm.0,
        );

        Commitment::from_projective(msm_variable_base(&points, &scalars))
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

fn compute_nth_lagrange_evaluation(
    domain: &EvaluationDomain,
    z_h_eval: &BlsScalar,
    z_challenge: &BlsScalar,
) -> BlsScalar {
    let n_fr = BlsScalar::from(domain.size() as u64);
    let eval_point = z_challenge * domain.group_gen;
    let denom = n_fr * (eval_point - BlsScalar::one());
    z_h_eval * denom.invert().unwrap()
}

#[warn(clippy::needless_range_loop)]
fn compute_barycentric_eval(
    evaluations: &[BlsScalar],
    point: &BlsScalar,
    domain: &EvaluationDomain,
) -> BlsScalar {
    use crate::util::batch_inversion;
    use rayon::iter::IntoParallelIterator;
    use rayon::prelude::*;

    let numerator =
        (point.pow(&[domain.size() as u64, 0, 0, 0]) - BlsScalar::one()) * domain.size_inv;

    // Indices with non-zero evaluations
    let non_zero_evaluations: Vec<usize> = (0..evaluations.len())
        .into_par_iter()
        .filter(|&i| {
            let evaluation = &evaluations[i];
            evaluation != &BlsScalar::zero()
        })
        .collect();

    // Only compute the denominators with non-zero evaluations
    let mut denominators: Vec<BlsScalar> = (0..non_zero_evaluations.len())
        .into_par_iter()
        .map(|i| {
            // index of non-zero evaluation
            let index = non_zero_evaluations[i];

            (domain.group_gen_inv.pow(&[index as u64, 0, 0, 0]) * point) - BlsScalar::one()
        })
        .collect();
    batch_inversion(&mut denominators);

    let result: BlsScalar = (0..non_zero_evaluations.len())
        .into_par_iter()
        .map(|i| {
            let eval_index = non_zero_evaluations[i];
            let eval = evaluations[eval_index];

            denominators[i] * eval
        })
        .sum();

    result * numerator
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_serialise_deserialise_proof() {
        let proof = Proof {
            a_comm: Commitment::default(),
            b_comm: Commitment::default(),
            c_comm: Commitment::default(),
            d_comm: Commitment::default(),
            z_comm: Commitment::default(),
            t_1_comm: Commitment::default(),
            t_2_comm: Commitment::default(),
            t_3_comm: Commitment::default(),
            t_4_comm: Commitment::default(),
            w_z_comm: Commitment::default(),
            w_zw_comm: Commitment::default(),
            evaluations: ProofEvaluations {
                a_eval: BlsScalar::random(&mut rand::thread_rng()),
                b_eval: BlsScalar::random(&mut rand::thread_rng()),
                c_eval: BlsScalar::random(&mut rand::thread_rng()),
                d_eval: BlsScalar::random(&mut rand::thread_rng()),
                a_next_eval: BlsScalar::random(&mut rand::thread_rng()),
                b_next_eval: BlsScalar::random(&mut rand::thread_rng()),
                d_next_eval: BlsScalar::random(&mut rand::thread_rng()),
                q_arith_eval: BlsScalar::random(&mut rand::thread_rng()),
                q_c_eval: BlsScalar::random(&mut rand::thread_rng()),
                q_l_eval: BlsScalar::random(&mut rand::thread_rng()),
                q_r_eval: BlsScalar::random(&mut rand::thread_rng()),
                left_sigma_eval: BlsScalar::random(&mut rand::thread_rng()),
                right_sigma_eval: BlsScalar::random(&mut rand::thread_rng()),
                out_sigma_eval: BlsScalar::random(&mut rand::thread_rng()),
                lin_poly_eval: BlsScalar::random(&mut rand::thread_rng()),
                perm_eval: BlsScalar::random(&mut rand::thread_rng()),
            },
        };

        let proof_bytes = proof.to_bytes();
        let got_proof = Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(got_proof, proof);
    }
}
