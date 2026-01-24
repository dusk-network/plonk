// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use core::ops;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
use ff::Field;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use crate::commitment_scheme::CommitKey;
use crate::compiler::prover::linearization_poly::ProofEvaluations;
use crate::error::Error;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::{
    ProverKey, VerifierKey, linearization_poly, proof::Proof, quotient_poly,
};
use crate::transcript::TranscriptProtocol;

use super::{Circuit, Composer};

/// Turbo Prover with processed keys
#[derive(Clone)]
pub struct Prover {
    label: Vec<u8>,
    pub(crate) prover_key: ProverKey,
    pub(crate) commit_key: CommitKey,
    pub(crate) verifier_key: VerifierKey,
    pub(crate) transcript: Transcript,
    pub(crate) size: usize,
    pub(crate) constraints: usize,
}

impl ops::Deref for Prover {
    type Target = ProverKey;

    fn deref(&self) -> &Self::Target {
        &self.prover_key
    }
}

impl Prover {
    pub(crate) fn new(
        label: Vec<u8>,
        prover_key: ProverKey,
        commit_key: CommitKey,
        verifier_key: VerifierKey,
        size: usize,
        constraints: usize,
    ) -> Self {
        let transcript =
            Transcript::base(label.as_slice(), &verifier_key, constraints);

        Self {
            label,
            prover_key,
            commit_key,
            verifier_key,
            transcript,
            size,
            constraints,
        }
    }

    /// adds blinding scalars to a witness vector
    ///
    /// appends:
    ///
    /// if hiding degree = 1: (b2*X^(n+1) + b1*X^n - b2*X - b1) + witnesses
    /// if hiding degree = 2: (b3*X^(n+2) + b2*X^(n+1) + b1*X^n - b3*X^2 - b2*X
    /// - b1) + witnesses
    fn blind_poly<R>(
        rng: &mut R,
        witnesses: &[BlsScalar],
        hiding_degree: usize,
        domain: &EvaluationDomain,
    ) -> Polynomial
    where
        R: RngCore + CryptoRng,
    {
        let mut w_vec_inverse = domain.ifft(witnesses);

        for i in 0..hiding_degree + 1 {
            let blinding_scalar = BlsScalar::random(&mut *rng);

            w_vec_inverse[i] -= blinding_scalar;
            w_vec_inverse.push(blinding_scalar);
        }

        Polynomial::from_coefficients_vec(w_vec_inverse)
    }

    fn prepare_serialize(
        &self,
    ) -> (usize, Vec<u8>, Vec<u8>, [u8; VerifierKey::SIZE]) {
        let prover_key = self.prover_key.to_var_bytes();
        let commit_key = self.commit_key.to_raw_var_bytes();
        let verifier_key = self.verifier_key.to_bytes();

        let label_len = self.label.len();
        let prover_key_len = prover_key.len();
        let commit_key_len = commit_key.len();
        let verifier_key_len = verifier_key.len();

        let size =
            48 + label_len + prover_key_len + commit_key_len + verifier_key_len;

        (size, prover_key, commit_key, verifier_key)
    }

    /// Serialized size in bytes
    pub fn serialized_size(&self) -> usize {
        self.prepare_serialize().0
    }

    /// Serialize the prover into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let (size, prover_key, commit_key, verifier_key) =
            self.prepare_serialize();
        let mut bytes = Vec::with_capacity(size);

        let label_len = self.label.len() as u64;
        let prover_key_len = prover_key.len() as u64;
        let commit_key_len = commit_key.len() as u64;
        let verifier_key_len = verifier_key.len() as u64;
        let size = self.size as u64;
        let constraints = self.constraints as u64;

        bytes.extend(label_len.to_be_bytes());
        bytes.extend(prover_key_len.to_be_bytes());
        bytes.extend(commit_key_len.to_be_bytes());
        bytes.extend(verifier_key_len.to_be_bytes());
        bytes.extend(size.to_be_bytes());
        bytes.extend(constraints.to_be_bytes());

        bytes.extend(self.label.as_slice());
        bytes.extend(prover_key);
        bytes.extend(commit_key);
        bytes.extend(verifier_key);

        bytes
    }

    /// Attempt to deserialize the prover from bytes generated via
    /// [`Self::to_bytes`]
    pub fn try_from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        let mut bytes = bytes.as_ref();

        if bytes.len() < 48 {
            return Err(Error::NotEnoughBytes);
        }

        let label_len = <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let label_len = u64::from_be_bytes(label_len) as usize;
        bytes = &bytes[8..];

        let prover_key_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let prover_key_len = u64::from_be_bytes(prover_key_len) as usize;
        bytes = &bytes[8..];

        let commit_key_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let commit_key_len = u64::from_be_bytes(commit_key_len) as usize;
        bytes = &bytes[8..];

        let verifier_key_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let verifier_key_len = u64::from_be_bytes(verifier_key_len) as usize;
        bytes = &bytes[8..];

        let size = <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let size = u64::from_be_bytes(size) as usize;
        bytes = &bytes[8..];

        let constraints =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let constraints = u64::from_be_bytes(constraints) as usize;
        bytes = &bytes[8..];

        if bytes.len()
            < label_len + prover_key_len + commit_key_len + verifier_key_len
        {
            return Err(Error::NotEnoughBytes);
        }

        let label = &bytes[..label_len];
        bytes = &bytes[label_len..];

        let prover_key = &bytes[..prover_key_len];
        bytes = &bytes[prover_key_len..];

        let commit_key = &bytes[..commit_key_len];
        bytes = &bytes[commit_key_len..];

        let verifier_key = &bytes[..verifier_key_len];

        let label = label.to_vec();
        let prover_key = ProverKey::from_slice(prover_key)?;

        // Safety: checked len
        let commit_key = unsafe { CommitKey::from_slice_unchecked(commit_key) };

        let verifier_key = VerifierKey::from_slice(verifier_key)?;

        Ok(Self::new(
            label,
            prover_key,
            commit_key,
            verifier_key,
            size,
            constraints,
        ))
    }

    /// Prove the circuit
    pub fn prove<C, R>(
        &self,
        rng: &mut R,
        circuit: &C,
    ) -> Result<(Proof, Vec<BlsScalar>), Error>
    where
        C: Circuit,
        R: RngCore + CryptoRng,
    {
        let prover = Composer::prove(self.constraints, circuit)?;

        let constraints = self.constraints;
        let size = self.size;

        let domain = EvaluationDomain::new(constraints)?;

        let mut transcript = self.transcript.clone();

        let public_inputs = prover.public_inputs();
        let public_input_indexes = prover.public_input_indexes();
        let dense_public_inputs = Composer::dense_public_inputs(
            &public_input_indexes,
            &public_inputs,
            self.size,
        );

        public_inputs
            .iter()
            .for_each(|pi| transcript.append_scalar(b"pi", pi));

        // round 1
        // convert wires to padded scalars
        let mut a_scalars = vec![BlsScalar::zero(); size];
        let mut b_scalars = vec![BlsScalar::zero(); size];
        let mut c_scalars = vec![BlsScalar::zero(); size];
        let mut d_scalars = vec![BlsScalar::zero(); size];

        prover
            .constraints
            .iter()
            .enumerate()
            .for_each(|(i, constraint)| {
                a_scalars[i] = prover[constraint.a];
                b_scalars[i] = prover[constraint.b];
                c_scalars[i] = prover[constraint.c];
                d_scalars[i] = prover[constraint.d];
            });

        let a_poly = Self::blind_poly(rng, &a_scalars, 1, &domain);
        let b_poly = Self::blind_poly(rng, &b_scalars, 1, &domain);
        let c_poly = Self::blind_poly(rng, &c_scalars, 1, &domain);
        let d_poly = Self::blind_poly(rng, &d_scalars, 1, &domain);

        // commit to wire polynomials
        // ([a(x)]_1, [b(x)]_1, [c(x)]_1, [d(x)]_1)
        let a_comm = self.commit_key.commit(&a_poly)?;
        let b_comm = self.commit_key.commit(&b_poly)?;
        let c_comm = self.commit_key.commit(&c_poly)?;
        let d_comm = self.commit_key.commit(&d_poly)?;

        // Add wire polynomial commitments to transcript
        transcript.append_commitment(b"a_comm", &a_comm);
        transcript.append_commitment(b"b_comm", &b_comm);
        transcript.append_commitment(b"c_comm", &c_comm);
        transcript.append_commitment(b"d_comm", &d_comm);

        // round 2
        // permutation challenges
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);

        let gamma = transcript.challenge_scalar(b"gamma");
        let sigma = [
            &self.prover_key.permutation.s_sigma_1.0,
            &self.prover_key.permutation.s_sigma_2.0,
            &self.prover_key.permutation.s_sigma_3.0,
            &self.prover_key.permutation.s_sigma_4.0,
        ];
        let wires = [
            a_scalars.as_slice(),
            b_scalars.as_slice(),
            c_scalars.as_slice(),
            d_scalars.as_slice(),
        ];
        let permutation = prover
            .perm
            .compute_permutation_vec(&domain, wires, &beta, &gamma, sigma);

        let z_poly = Self::blind_poly(rng, &permutation, 2, &domain);
        let z_comm = self.commit_key.commit(&z_poly)?;
        transcript.append_commitment(b"z_comm", &z_comm);

        // round 3
        // compute quotient challenge alpha
        let alpha = transcript.challenge_scalar(b"alpha");
        let range_sep_challenge =
            transcript.challenge_scalar(b"range separation challenge");
        let logic_sep_challenge =
            transcript.challenge_scalar(b"logic separation challenge");
        let fixed_base_sep_challenge =
            transcript.challenge_scalar(b"fixed base separation challenge");
        let var_base_sep_challenge =
            transcript.challenge_scalar(b"variable base separation challenge");

        // compute public inputs polynomial
        let pi_poly = domain.ifft(&dense_public_inputs);
        let pi_poly = Polynomial::from_coefficients_vec(pi_poly);

        // compute quotient polynomial
        let wires = (&a_poly, &b_poly, &c_poly, &d_poly);
        let args = &(
            alpha,
            beta,
            gamma,
            range_sep_challenge,
            logic_sep_challenge,
            fixed_base_sep_challenge,
            var_base_sep_challenge,
        );
        let t_poly = quotient_poly::compute(
            &domain,
            &self.prover_key,
            &z_poly,
            wires,
            &pi_poly,
            args,
        )?;

        // split quotient polynomial into 4 degree `n` polynomials
        let domain_size = domain.size();

        let mut t_low_vec = t_poly[0..domain_size].to_vec();
        let mut t_mid_vec = t_poly[domain_size..2 * domain_size].to_vec();
        let mut t_high_vec = t_poly[2 * domain_size..3 * domain_size].to_vec();
        let mut t_fourth_vec = t_poly[3 * domain_size..].to_vec();

        // select 3 blinding factors for the quotient splitted polynomials
        let b_12 = BlsScalar::random(&mut *rng);
        let b_13 = BlsScalar::random(&mut *rng);
        let b_14 = BlsScalar::random(&mut *rng);

        // t_low'(X) + b_12*X^n
        t_low_vec.push(b_12);

        // t_mid'(X) - b_12 + b_13*X^n
        t_mid_vec[0] -= b_12;
        t_mid_vec.push(b_13);

        // t_high'(X) - b_13 + b_14*X^n
        t_high_vec[0] -= b_13;
        t_high_vec.push(b_14);

        // t_fourth'(X) - b_14
        t_fourth_vec[0] -= b_14;

        let t_low_poly = Polynomial::from_coefficients_vec(t_low_vec);
        let t_mid_poly = Polynomial::from_coefficients_vec(t_mid_vec);
        let t_high_poly = Polynomial::from_coefficients_vec(t_high_vec);
        let t_fourth_poly = Polynomial::from_coefficients_vec(t_fourth_vec);

        // commit to split quotient polynomial
        let t_low_comm = self.commit_key.commit(&t_low_poly)?;
        let t_mid_comm = self.commit_key.commit(&t_mid_poly)?;
        let t_high_comm = self.commit_key.commit(&t_high_poly)?;
        let t_fourth_comm = self.commit_key.commit(&t_fourth_poly)?;

        // add quotient polynomial commitments to transcript
        transcript.append_commitment(b"t_low_comm", &t_low_comm);
        transcript.append_commitment(b"t_mid_comm", &t_mid_comm);
        transcript.append_commitment(b"t_high_comm", &t_high_comm);
        transcript.append_commitment(b"t_fourth_comm", &t_fourth_comm);

        // round 4
        // compute evaluation challenge 'z'
        let z_challenge = transcript.challenge_scalar(b"z_challenge");

        // compute opening evaluations
        let a_eval = a_poly.evaluate(&z_challenge);
        let b_eval = b_poly.evaluate(&z_challenge);
        let c_eval = c_poly.evaluate(&z_challenge);
        let d_eval = d_poly.evaluate(&z_challenge);

        let s_sigma_1_eval = self
            .prover_key
            .permutation
            .s_sigma_1
            .0
            .evaluate(&z_challenge);
        let s_sigma_2_eval = self
            .prover_key
            .permutation
            .s_sigma_2
            .0
            .evaluate(&z_challenge);
        let s_sigma_3_eval = self
            .prover_key
            .permutation
            .s_sigma_3
            .0
            .evaluate(&z_challenge);

        let z_eval = z_poly.evaluate(&(z_challenge * domain.group_gen));

        // add opening evaluations to transcript.
        transcript.append_scalar(b"a_eval", &a_eval);
        transcript.append_scalar(b"b_eval", &b_eval);
        transcript.append_scalar(b"c_eval", &c_eval);
        transcript.append_scalar(b"d_eval", &d_eval);

        transcript.append_scalar(b"s_sigma_1_eval", &s_sigma_1_eval);
        transcript.append_scalar(b"s_sigma_2_eval", &s_sigma_2_eval);
        transcript.append_scalar(b"s_sigma_3_eval", &s_sigma_3_eval);

        transcript.append_scalar(b"z_eval", &z_eval);

        // compute shifted evaluations
        let a_w_eval = a_poly.evaluate(&(z_challenge * domain.group_gen));
        let b_w_eval = b_poly.evaluate(&(z_challenge * domain.group_gen));
        let d_w_eval = d_poly.evaluate(&(z_challenge * domain.group_gen));

        // compute selector evaluations
        let q_arith_eval =
            self.prover_key.arithmetic.q_arith.0.evaluate(&z_challenge);
        let q_c_eval = self.prover_key.logic.q_c.0.evaluate(&z_challenge);
        let q_l_eval = self.prover_key.fixed_base.q_l.0.evaluate(&z_challenge);
        let q_r_eval = self.prover_key.fixed_base.q_r.0.evaluate(&z_challenge);

        // add shifted evaluations to transcript
        transcript.append_scalar(b"a_w_eval", &a_w_eval);
        transcript.append_scalar(b"b_w_eval", &b_w_eval);
        transcript.append_scalar(b"d_w_eval", &d_w_eval);

        // add selector evaluations to transcript.
        transcript.append_scalar(b"q_arith_eval", &q_arith_eval);
        transcript.append_scalar(b"q_c_eval", &q_c_eval);
        transcript.append_scalar(b"q_l_eval", &q_l_eval);
        transcript.append_scalar(b"q_r_eval", &q_r_eval);

        let evaluations = ProofEvaluations {
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
        };

        // round 5
        // compute the challenge 'v'
        let v_challenge = transcript.challenge_scalar(b"v_challenge");

        // compute linearization polynomial
        let r_poly = linearization_poly::compute(
            &self.prover_key,
            &(
                alpha,
                beta,
                gamma,
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
                z_challenge,
            ),
            &z_poly,
            &evaluations,
            &domain,
            &t_low_poly,
            &t_mid_poly,
            &t_high_poly,
            &t_fourth_poly,
            &public_inputs,
        );

        // compute the opening proof polynomial 'W_z(X)'
        let aggregate_witness = CommitKey::compute_aggregate_witness(
            &[
                r_poly,
                a_poly.clone(),
                b_poly.clone(),
                c_poly,
                d_poly.clone(),
                self.prover_key.permutation.s_sigma_1.0.clone(),
                self.prover_key.permutation.s_sigma_2.0.clone(),
                self.prover_key.permutation.s_sigma_3.0.clone(),
            ],
            &z_challenge,
            &v_challenge,
        );
        let w_z_chall_comm = self.commit_key.commit(&aggregate_witness)?;

        // compute the shifted challenge 'v_w'
        let v_w_challenge = transcript.challenge_scalar(b"v_w_challenge");

        // compute the shifted opening proof polynomial 'W_zw(X)'
        let shifted_aggregate_witness = CommitKey::compute_aggregate_witness(
            &[z_poly, a_poly, b_poly, d_poly],
            &(z_challenge * domain.group_gen),
            &v_w_challenge,
        );
        let w_z_chall_w_comm =
            self.commit_key.commit(&shifted_aggregate_witness)?;

        let proof = Proof {
            a_comm,
            b_comm,
            c_comm,
            d_comm,

            z_comm,

            t_low_comm,
            t_mid_comm,
            t_high_comm,
            t_fourth_comm,

            w_z_chall_comm,
            w_z_chall_w_comm,

            evaluations,
        };

        Ok((proof, public_inputs))
    }
}
