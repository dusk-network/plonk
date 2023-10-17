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
use crate::error::Error;
use crate::fft::{EvaluationDomain, Polynomial as FftPolynomial};
use crate::proof_system::proof::Proof;
use crate::proof_system::{
    linearization_poly, quotient_poly, ProverKey, VerifierKey,
};
use crate::transcript::TranscriptProtocol;

use super::{Builder, Circuit, Composer};

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
    fn blind_poly<R>(
        rng: &mut R,
        witnesses: &[BlsScalar],
        hiding_degree: usize,
        domain: &EvaluationDomain,
    ) -> FftPolynomial
    where
        R: RngCore + CryptoRng,
    {
        let mut w_vec_inverse = domain.ifft(witnesses);

        for i in 0..hiding_degree + 1 {
            let blinding_scalar = BlsScalar::random(&mut *rng);

            w_vec_inverse[i] -= blinding_scalar;
            w_vec_inverse.push(blinding_scalar);
        }

        FftPolynomial::from_coefficients_vec(w_vec_inverse)
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
        let prover = Builder::prove(self.constraints, circuit)?;

        let constraints = self.constraints;
        let size = self.size;

        let domain = EvaluationDomain::new(constraints)?;

        let mut transcript = self.transcript.clone();

        let public_inputs = prover.public_inputs();
        let public_input_indexes = prover.public_input_indexes();
        let dense_public_inputs = Builder::dense_public_inputs(
            &public_input_indexes,
            &public_inputs,
            self.size,
        );

        public_inputs
            .iter()
            .for_each(|pi| transcript.append_scalar(b"pi", pi));

        // round 1
        // convert wires to padded scalars
        let mut a_w_scalar = vec![BlsScalar::zero(); size];
        let mut b_w_scalar = vec![BlsScalar::zero(); size];
        let mut o_w_scalar = vec![BlsScalar::zero(); size];
        let mut d_w_scalar = vec![BlsScalar::zero(); size];

        prover.constraints.iter().enumerate().for_each(|(i, c)| {
            a_w_scalar[i] = prover[c.w_a];
            b_w_scalar[i] = prover[c.w_b];
            o_w_scalar[i] = prover[c.w_o];
            d_w_scalar[i] = prover[c.w_d];
        });

        let a_w_poly = Self::blind_poly(rng, &a_w_scalar, 1, &domain);
        let b_w_poly = Self::blind_poly(rng, &b_w_scalar, 1, &domain);
        let o_w_poly = Self::blind_poly(rng, &o_w_scalar, 1, &domain);
        let d_w_poly = Self::blind_poly(rng, &d_w_scalar, 1, &domain);

        // commit to wire polynomials
        // ([a(x)]_1, [b(x)]_1, [c(x)]_1, [d(x)]_1)
        let a_w_poly_commit = self.commit_key.commit(&a_w_poly)?;
        let b_w_poly_commit = self.commit_key.commit(&b_w_poly)?;
        let o_w_poly_commit = self.commit_key.commit(&o_w_poly)?;
        let d_w_poly_commit = self.commit_key.commit(&d_w_poly)?;

        // Add wire polynomial commitments to transcript
        transcript.append_commitment(b"a_w", &a_w_poly_commit);
        transcript.append_commitment(b"b_w", &b_w_poly_commit);
        transcript.append_commitment(b"c_w", &o_w_poly_commit);
        transcript.append_commitment(b"d_w", &d_w_poly_commit);

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
            a_w_scalar.as_slice(),
            b_w_scalar.as_slice(),
            o_w_scalar.as_slice(),
            d_w_scalar.as_slice(),
        ];
        let permutation = prover
            .perm
            .compute_permutation_vec(&domain, wires, &beta, &gamma, sigma);

        let z_poly = Self::blind_poly(rng, &permutation, 2, &domain);
        let z_poly_commit = self.commit_key.commit(&z_poly)?;
        transcript.append_commitment(b"z", &z_poly_commit);

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
        let pi_poly = FftPolynomial::from_coefficients_vec(pi_poly);

        // compute quotient polynomial
        let wires = (&a_w_poly, &b_w_poly, &o_w_poly, &d_w_poly);
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
        let t_low_poly = FftPolynomial::from_coefficients_vec(
            t_poly[0..domain_size].to_vec(),
        );
        let t_mid_poly = FftPolynomial::from_coefficients_vec(
            t_poly[domain_size..2 * domain_size].to_vec(),
        );
        let t_high_poly = FftPolynomial::from_coefficients_vec(
            t_poly[2 * domain_size..3 * domain_size].to_vec(),
        );
        let t_4_poly = FftPolynomial::from_coefficients_vec(
            t_poly[3 * domain_size..].to_vec(),
        );

        // commit to split quotient polynomial
        let t_low_commit = self.commit_key.commit(&t_low_poly)?;
        let t_mid_commit = self.commit_key.commit(&t_mid_poly)?;
        let t_high_commit = self.commit_key.commit(&t_high_poly)?;
        let t_4_commit = self.commit_key.commit(&t_4_poly)?;

        // add quotient polynomial commitments to transcript
        transcript.append_commitment(b"t_low", &t_low_commit);
        transcript.append_commitment(b"t_mid", &t_mid_commit);
        transcript.append_commitment(b"t_high", &t_high_commit);
        transcript.append_commitment(b"t_4", &t_4_commit);

        // round 4
        // compute evaluation challenge 'z'
        let z_challenge = transcript.challenge_scalar(b"z_challenge");

        // round 5
        // compute linearization polynomial
        let (r_poly, evaluations) = linearization_poly::compute(
            &domain,
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
            &a_w_poly,
            &b_w_poly,
            &o_w_poly,
            &d_w_poly,
            &t_poly,
            &z_poly,
        );

        // add evaluations to transcript.
        transcript.append_scalar(b"a_eval", &evaluations.proof.a_eval);
        transcript.append_scalar(b"b_eval", &evaluations.proof.b_eval);
        transcript.append_scalar(b"c_eval", &evaluations.proof.c_eval);
        transcript.append_scalar(b"d_eval", &evaluations.proof.d_eval);
        transcript
            .append_scalar(b"a_next_eval", &evaluations.proof.a_next_eval);
        transcript
            .append_scalar(b"b_next_eval", &evaluations.proof.b_next_eval);
        transcript
            .append_scalar(b"d_next_eval", &evaluations.proof.d_next_eval);
        transcript.append_scalar(
            b"s_sigma_1_eval",
            &evaluations.proof.s_sigma_1_eval,
        );
        transcript.append_scalar(
            b"s_sigma_2_eval",
            &evaluations.proof.s_sigma_2_eval,
        );
        transcript.append_scalar(
            b"s_sigma_3_eval",
            &evaluations.proof.s_sigma_3_eval,
        );
        transcript
            .append_scalar(b"q_arith_eval", &evaluations.proof.q_arith_eval);
        transcript.append_scalar(b"q_c_eval", &evaluations.proof.q_c_eval);
        transcript.append_scalar(b"q_l_eval", &evaluations.proof.q_l_eval);
        transcript.append_scalar(b"q_r_eval", &evaluations.proof.q_r_eval);
        transcript.append_scalar(b"perm_eval", &evaluations.proof.perm_eval);
        transcript.append_scalar(b"t_eval", &evaluations.t_eval);
        transcript.append_scalar(b"r_eval", &evaluations.proof.r_poly_eval);

        // compute Openings using KZG10
        let z_n = z_challenge.pow(&[domain_size as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * domain_size as u64, 0, 0, 0]);
        let z_three_n = z_challenge.pow(&[3 * domain_size as u64, 0, 0, 0]);

        let a = &t_low_poly;
        let b = &t_mid_poly * &z_n;
        let c = &t_high_poly * &z_two_n;
        let d = &t_4_poly * &z_three_n;
        let abc = &(a + &b) + &c;

        let quot = &abc + &d;

        // compute aggregate witness to polynomials evaluated at the evaluation
        // challenge z. The challenge v is selected inside
        let aggregate_witness = self.commit_key.compute_aggregate_witness(
            &[
                quot,
                r_poly,
                a_w_poly.clone(),
                b_w_poly.clone(),
                o_w_poly,
                d_w_poly.clone(),
                self.prover_key.permutation.s_sigma_1.0.clone(),
                self.prover_key.permutation.s_sigma_2.0.clone(),
                self.prover_key.permutation.s_sigma_3.0.clone(),
            ],
            &z_challenge,
            &mut transcript,
        );
        let w_z_chall_comm = self.commit_key.commit(&aggregate_witness)?;

        // compute aggregate witness to polynomials evaluated at the shifted
        // evaluation challenge
        let shifted_aggregate_witness =
            self.commit_key.compute_aggregate_witness(
                &[z_poly, a_w_poly, b_w_poly, d_w_poly],
                &(z_challenge * domain.group_gen),
                &mut transcript,
            );
        let w_z_chall_w_comm =
            self.commit_key.commit(&shifted_aggregate_witness)?;

        let proof = Proof {
            a_comm: a_w_poly_commit,
            b_comm: b_w_poly_commit,
            c_comm: o_w_poly_commit,
            d_comm: d_w_poly_commit,

            z_comm: z_poly_commit,

            t_low_comm: t_low_commit,
            t_mid_comm: t_mid_commit,
            t_high_comm: t_high_commit,
            t_4_comm: t_4_commit,

            w_z_chall_comm,
            w_z_chall_w_comm,

            evaluations: evaluations.proof,
        };

        Ok((proof, public_inputs))
    }
}
