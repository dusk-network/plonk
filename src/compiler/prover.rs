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

use super::{Circuit, Composer, PlonkVersion};
use crate::commitment_scheme::{CommitKey, Commitment};
use crate::compiler::prover::linearization_poly::ProofEvaluations;
use crate::error::Error;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::proof::Proof;
use crate::proof_system::{
    ProverKey, VerifierKey, linearization_poly, quotient_poly,
};
use crate::transcript::TranscriptProtocol;
use crate::util::batch_inversion;

/// Turbo Prover with processed keys
#[derive(Clone)]
pub struct Prover {
    label: Vec<u8>,
    pub(crate) prover_key: ProverKey,
    pub(crate) commit_key: CommitKey,
    pub(crate) verifier_key: VerifierKey,
    pub(crate) transcript: Transcript,
    sigma_evaluations: [Vec<BlsScalar>; 4],
    domain: EvaluationDomain,
    quotient_domain: EvaluationDomain,
    vanishing_coset_inverses: [BlsScalar; 8],
    pub(crate) size: usize,
    pub(crate) constraints: usize,
    public_input_indexes: Vec<usize>,
}

// The low 32 bits are deliberately all ones. Previous 32-bit decoders read
// this as the label length and must reject new-format provers instead of
// truncating away a version bit and silently dropping the row layout.
const PROVER_FORMAT_V2_MAGIC: u64 = 0x5052_5632_FFFF_FFFF;

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
        public_input_indexes: Vec<usize>,
    ) -> Result<Self, Error> {
        if constraints.checked_next_power_of_two() != Some(size)
            || prover_key.n != size
            || public_input_indexes
                .iter()
                .any(|index| *index >= constraints)
            || public_input_indexes
                .windows(2)
                .any(|indexes| indexes[0] >= indexes[1])
        {
            return Err(dusk_bytes::Error::InvalidData.into());
        }

        let domain = EvaluationDomain::new(constraints)?;
        let quotient_size = domain
            .size()
            .checked_mul(8)
            .ok_or(dusk_bytes::Error::InvalidData)?;
        let quotient_domain = EvaluationDomain::new(quotient_size)?;

        // Compilation constructs these evaluations for this exact quotient
        // domain, while checked decoding validates their domain, length, and
        // values before construction reaches here. Keep the checks local too,
        // so malformed source data can never become cached proving state.
        let vanishing_evaluations = &prover_key.v_h_coset_8n().evals;
        if vanishing_evaluations.len() != quotient_domain.size()
            || vanishing_evaluations
                .iter()
                .any(|evaluation| *evaluation == BlsScalar::zero())
        {
            return Err(dusk_bytes::Error::InvalidData.into());
        }
        let first_period = vanishing_evaluations
            .get(..8)
            .ok_or(dusk_bytes::Error::InvalidData)?;
        let mut vanishing_coset_inverses = [BlsScalar::zero(); 8];
        vanishing_coset_inverses.copy_from_slice(first_period);
        batch_inversion(&mut vanishing_coset_inverses);

        let transcript =
            Transcript::base(label.as_slice(), &verifier_key, constraints);
        let sigma_evaluations = [
            domain.fft(&prover_key.permutation.s_sigma_1.0),
            domain.fft(&prover_key.permutation.s_sigma_2.0),
            domain.fft(&prover_key.permutation.s_sigma_3.0),
            domain.fft(&prover_key.permutation.s_sigma_4.0),
        ];

        Ok(Self {
            label,
            prover_key,
            commit_key,
            verifier_key,
            transcript,
            sigma_evaluations,
            domain,
            quotient_domain,
            vanishing_coset_inverses,
            size,
            constraints,
            public_input_indexes,
        })
    }

    /// adds blinding scalars to a witness vector
    ///
    /// appends:
    ///
    /// if hiding degree = 1: (b2*X^(n+1) + b1*X^n - b2*X - b1) + witnesses
    /// if hiding degree = 2: (b3*X^(n+2) + b2*X^(n+1) + b1*X^n - b3*X^2 - b2*X
    /// - b1) + witnesses
    pub(crate) fn blind_poly<R>(
        rng: &mut R,
        witnesses: &[BlsScalar],
        hiding_degree: usize,
        domain: &EvaluationDomain,
    ) -> Polynomial
    where
        R: RngCore + CryptoRng,
    {
        let blinders: Vec<_> = (0..=hiding_degree)
            .map(|_| BlsScalar::random(&mut *rng))
            .collect();
        Self::blind_poly_with_blinders(witnesses, &blinders, domain)
    }

    fn blind_poly_with_blinders(
        witnesses: &[BlsScalar],
        blinders: &[BlsScalar],
        domain: &EvaluationDomain,
    ) -> Polynomial {
        let mut coefficients = domain.ifft(witnesses);

        for (i, blinding_scalar) in blinders.iter().copied().enumerate() {
            coefficients[i] -= blinding_scalar;
            coefficients.push(blinding_scalar);
        }

        Polynomial::from_coefficients_vec(coefficients)
    }

    fn sample_wire_blinders<R>(rng: &mut R) -> [[BlsScalar; 2]; 4]
    where
        R: RngCore + CryptoRng,
    {
        core::array::from_fn(|_| {
            core::array::from_fn(|_| BlsScalar::random(&mut *rng))
        })
    }

    fn blind_wire_polynomials(
        witnesses: [&[BlsScalar]; 4],
        blinders: &[[BlsScalar; 2]; 4],
        domain: &EvaluationDomain,
    ) -> [Polynomial; 4] {
        let blind = |i: usize| {
            let blinders = blinders[i].as_slice();
            Self::blind_poly_with_blinders(witnesses[i], blinders, domain)
        };
        #[cfg(feature = "std")]
        {
            let ((a, b), (c, d)) = rayon::join(
                || rayon::join(|| blind(0), || blind(1)),
                || rayon::join(|| blind(2), || blind(3)),
            );
            [a, b, c, d]
        }

        #[cfg(not(feature = "std"))]
        {
            [blind(0), blind(1), blind(2), blind(3)]
        }
    }

    fn commit_polynomials(
        &self,
        polynomials: [&Polynomial; 4],
    ) -> Result<[Commitment; 4], Error> {
        #[cfg(feature = "std")]
        {
            let commit = |i: usize| self.commit_key.commit(polynomials[i]);
            let ((a, b), (c, d)) = rayon::join(
                || rayon::join(|| commit(0), || commit(1)),
                || rayon::join(|| commit(2), || commit(3)),
            );
            Ok([a?, b?, c?, d?])
        }

        #[cfg(not(feature = "std"))]
        {
            Ok([
                self.commit_key.commit(polynomials[0])?,
                self.commit_key.commit(polynomials[1])?,
                self.commit_key.commit(polynomials[2])?,
                self.commit_key.commit(polynomials[3])?,
            ])
        }
    }

    fn prepare_serialize(
        &self,
    ) -> (usize, Vec<u8>, Vec<u8>, [u8; VerifierKey::SIZE]) {
        // Quotient caches are derived state. Omitting them preserves the
        // format and ensures checked decoding always rebuilds fresh values.
        let prover_key = self.prover_key.to_var_bytes();
        let commit_key = self.commit_key.to_raw_var_bytes();
        let verifier_key = self.verifier_key.to_bytes();

        let label_len = self.label.len();
        let prover_key_len = prover_key.len();
        let commit_key_len = commit_key.len();
        let verifier_key_len = verifier_key.len();

        let public_input_indexes_len =
            self.public_input_indexes.len() * u64::SIZE;
        let size = 8 * u64::SIZE
            + label_len
            + prover_key_len
            + commit_key_len
            + verifier_key_len
            + public_input_indexes_len;

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

        bytes.extend(PROVER_FORMAT_V2_MAGIC.to_be_bytes());
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
        bytes.extend((self.public_input_indexes.len() as u64).to_be_bytes());
        for index in &self.public_input_indexes {
            bytes.extend((*index as u64).to_be_bytes());
        }

        bytes
    }

    /// Attempt to deserialize the prover from bytes generated via
    /// [`Self::to_bytes`]
    pub fn try_from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        let mut bytes = bytes.as_ref();

        if bytes.len() < 56 {
            return Err(Error::NotEnoughBytes);
        }

        let magic = <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        if u64::from_be_bytes(magic) != PROVER_FORMAT_V2_MAGIC {
            return Err(dusk_bytes::Error::InvalidData.into());
        }
        bytes = &bytes[8..];

        let label_len = <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let label_len = usize::try_from(u64::from_be_bytes(label_len))
            .map_err(|_| dusk_bytes::Error::InvalidData)?;
        bytes = &bytes[8..];

        let prover_key_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let prover_key_len =
            usize::try_from(u64::from_be_bytes(prover_key_len))
                .map_err(|_| dusk_bytes::Error::InvalidData)?;
        bytes = &bytes[8..];

        let commit_key_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let commit_key_len =
            usize::try_from(u64::from_be_bytes(commit_key_len))
                .map_err(|_| dusk_bytes::Error::InvalidData)?;
        bytes = &bytes[8..];

        let verifier_key_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let verifier_key_len =
            usize::try_from(u64::from_be_bytes(verifier_key_len))
                .map_err(|_| dusk_bytes::Error::InvalidData)?;
        bytes = &bytes[8..];

        let size = <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let size = usize::try_from(u64::from_be_bytes(size))
            .map_err(|_| dusk_bytes::Error::InvalidData)?;
        bytes = &bytes[8..];

        let constraints =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let constraints = usize::try_from(u64::from_be_bytes(constraints))
            .map_err(|_| dusk_bytes::Error::InvalidData)?;
        bytes = &bytes[8..];

        let required_len = label_len
            .checked_add(prover_key_len)
            .and_then(|len| len.checked_add(commit_key_len))
            .and_then(|len| len.checked_add(verifier_key_len))
            .ok_or(Error::NotEnoughBytes)?;

        if bytes.len() < required_len {
            return Err(Error::NotEnoughBytes);
        }

        if constraints.checked_next_power_of_two() != Some(size) {
            return Err(dusk_bytes::Error::InvalidData.into());
        }

        let label = &bytes[..label_len];
        bytes = &bytes[label_len..];

        let prover_key = &bytes[..prover_key_len];
        bytes = &bytes[prover_key_len..];

        let commit_key = &bytes[..commit_key_len];
        bytes = &bytes[commit_key_len..];

        let verifier_key = &bytes[..verifier_key_len];
        bytes = &bytes[verifier_key_len..];

        if bytes.len() < u64::SIZE {
            return Err(Error::NotEnoughBytes);
        }
        let public_input_indexes_len =
            u64::from_be_bytes(bytes[..u64::SIZE].try_into().expect("checked"));
        let public_input_indexes_len =
            usize::try_from(public_input_indexes_len)
                .map_err(|_| dusk_bytes::Error::InvalidData)?;
        bytes = &bytes[u64::SIZE..];

        if public_input_indexes_len > constraints {
            return Err(dusk_bytes::Error::InvalidData.into());
        }
        let indexes_bytes_len = public_input_indexes_len
            .checked_mul(u64::SIZE)
            .ok_or(dusk_bytes::Error::InvalidData)?;
        if bytes.len() != indexes_bytes_len {
            return Err(dusk_bytes::Error::InvalidData.into());
        }
        let public_input_indexes = bytes
            .as_chunks::<{ u64::SIZE }>()
            .0
            .iter()
            .map(|bytes| {
                let index = u64::from_be_bytes(*bytes);
                usize::try_from(index)
                    .map_err(|_| dusk_bytes::Error::InvalidData)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let label = label.to_vec();
        let prover_key = ProverKey::from_slice(prover_key)?;

        if prover_key.n != size {
            return Err(dusk_bytes::Error::InvalidData.into());
        }

        let commit_key = CommitKey::from_raw_var_bytes(commit_key)?;

        let verifier_key = VerifierKey::from_slice(verifier_key)?;

        Self::new(
            label,
            prover_key,
            commit_key,
            verifier_key,
            size,
            constraints,
            public_input_indexes,
        )
    }

    /// Prove the circuit using the current (latest) proving behavior.
    pub fn prove<C, R>(
        &self,
        rng: &mut R,
        circuit: &C,
    ) -> Result<(Proof, Vec<BlsScalar>), Error>
    where
        C: Circuit,
        R: RngCore + CryptoRng,
    {
        self.prove_with_version(rng, circuit, PlonkVersion::current())
    }

    /// Prove the circuit using an explicitly selected version.
    pub fn prove_with_version<C, R>(
        &self,
        rng: &mut R,
        circuit: &C,
        version: PlonkVersion,
    ) -> Result<(Proof, Vec<BlsScalar>), Error>
    where
        C: Circuit,
        R: RngCore + CryptoRng,
    {
        match version {
            PlonkVersion::V1 => Err(Error::UnsupportedProvingVersion),
            PlonkVersion::V2 => self.prove_legacy(rng, circuit, version),
            PlonkVersion::V3 => self.prove_inner(rng, circuit, version),
        }
    }

    fn prove_legacy<C, R>(
        &self,
        rng: &mut R,
        circuit: &C,
        version: PlonkVersion,
    ) -> Result<(Proof, Vec<BlsScalar>), Error>
    where
        C: Circuit,
        R: RngCore + CryptoRng,
    {
        #[cfg(feature = "legacy-proving")]
        {
            self.prove_inner(rng, circuit, version)
        }

        #[cfg(not(feature = "legacy-proving"))]
        {
            let _ = (rng, circuit, version);
            Err(Error::LegacyProvingDisabled)
        }
    }

    fn transcript_for_version(&self, version: PlonkVersion) -> Transcript {
        match version {
            PlonkVersion::V1 | PlonkVersion::V2 => self.transcript.clone(),
            PlonkVersion::V3 => Transcript::base_v3(
                self.label.as_slice(),
                &self.verifier_key,
                self.constraints,
            ),
        }
    }

    fn prove_inner<C, R>(
        &self,
        rng: &mut R,
        circuit: &C,
        version: PlonkVersion,
    ) -> Result<(Proof, Vec<BlsScalar>), Error>
    where
        C: Circuit,
        R: RngCore + CryptoRng,
    {
        let prover = Composer::prove(self.constraints, circuit)?;

        let size = self.size;
        let domain = self.domain;

        let mut transcript = self.transcript_for_version(version);

        let public_inputs_len = prover.public_inputs.len();
        if public_inputs_len != self.public_input_indexes.len() {
            return Err(Error::InconsistentPublicInputsLen {
                expected: self.public_input_indexes.len(),
                provided: public_inputs_len,
            });
        }
        let public_inputs = self
            .public_input_indexes
            .iter()
            .map(|index| {
                prover
                    .public_inputs
                    .get(index)
                    .copied()
                    .ok_or(Error::PublicInputNotFound { index: *index })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dense_public_inputs = Composer::dense_public_inputs(
            &self.public_input_indexes,
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

        let wire_blinders = Self::sample_wire_blinders(rng);

        let [a_poly, b_poly, c_poly, d_poly] = Self::blind_wire_polynomials(
            [&a_scalars, &b_scalars, &c_scalars, &d_scalars],
            &wire_blinders,
            &domain,
        );

        // commit to wire polynomials
        // ([a(x)]_1, [b(x)]_1, [c(x)]_1, [d(x)]_1)
        let [a_comm, b_comm, c_comm, d_comm] =
            self.commit_polynomials([&a_poly, &b_poly, &c_poly, &d_poly])?;

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
            self.sigma_evaluations[0].as_slice(),
            self.sigma_evaluations[1].as_slice(),
            self.sigma_evaluations[2].as_slice(),
            self.sigma_evaluations[3].as_slice(),
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
            &self.quotient_domain,
            &self.prover_key,
            &z_poly,
            wires,
            &pi_poly,
            &self.vanishing_coset_inverses,
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
        let [t_low_comm, t_mid_comm, t_high_comm, t_fourth_comm] = self
            .commit_polynomials([
                &t_low_poly,
                &t_mid_poly,
                &t_high_poly,
                &t_fourth_poly,
            ])?;

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
        // These selector/constant polynomials are shared across widgets.
        // Evaluate them from the arithmetic key to match transcript-seeded
        // commitments under the corresponding labels.
        let q_c_eval = self.prover_key.arithmetic.q_c.0.evaluate(&z_challenge);
        let q_l_eval = self.prover_key.arithmetic.q_l.0.evaluate(&z_challenge);
        let q_r_eval = self.prover_key.arithmetic.q_r.0.evaluate(&z_challenge);

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
            &linearization_poly::LinearizationChallenges {
                alpha,
                beta,
                gamma,
                range_separation: range_sep_challenge,
                logic_separation: logic_sep_challenge,
                fixed_base_separation: fixed_base_sep_challenge,
                variable_base_separation: var_base_sep_challenge,
                z: z_challenge,
            },
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
                &r_poly,
                &a_poly,
                &b_poly,
                &c_poly,
                &d_poly,
                &self.prover_key.permutation.s_sigma_1.0,
                &self.prover_key.permutation.s_sigma_2.0,
                &self.prover_key.permutation.s_sigma_3.0,
                // Bind selector evaluations (q_*) used inside the verifier
                // linearization commitment to their committed polynomials
                // by including them in the same batched opening at `z`.
                &self.prover_key.arithmetic.q_arith.0,
                &self.prover_key.arithmetic.q_c.0,
                &self.prover_key.arithmetic.q_l.0,
                &self.prover_key.arithmetic.q_r.0,
            ],
            &z_challenge,
            &v_challenge,
        );
        let w_z_chall_comm = self.commit_key.commit(&aggregate_witness)?;

        // compute the shifted challenge 'v_w'
        let v_w_challenge = transcript.challenge_scalar(b"v_w_challenge");

        // compute the shifted opening proof polynomial 'W_zw(X)'
        let shifted_aggregate_witness = CommitKey::compute_aggregate_witness(
            &[&z_poly, &a_poly, &b_poly, &d_poly],
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

#[cfg(test)]
mod tests {
    use dusk_bls12_381::BlsScalar;
    use dusk_bytes::{DeserializableSlice, Serializable};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::Prover;
    use crate::error::Error;
    use crate::fft::EvaluationDomain;
    use crate::prelude::{
        Circuit, Compiler, Composer, Constraint, PublicParameters,
    };

    #[derive(Default)]
    struct MinimalCircuit;

    impl Circuit for MinimalCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w = composer.append_witness(BlsScalar::from(7u64));
            composer.assert_equal_constant(w, BlsScalar::from(7u64), None);
            Ok(())
        }
    }

    struct PublicInputRows {
        rows: [bool; 2],
        value: BlsScalar,
    }

    impl Default for PublicInputRows {
        fn default() -> Self {
            Self {
                rows: [true, false],
                value: BlsScalar::zero(),
            }
        }
    }

    impl Circuit for PublicInputRows {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            for include_public_input in self.rows {
                let constraint = Constraint::new()
                    .left(1)
                    .a(Composer::ONE)
                    .right(1)
                    .b(Composer::ZERO);
                let constraint = if include_public_input {
                    constraint.public(self.value)
                } else {
                    constraint
                };
                composer.gate_add(constraint);
            }
            Ok(())
        }
    }

    fn assert_deserialization_error_without_panic(bytes: &[u8]) {
        let result = std::panic::catch_unwind(|| Prover::try_from_bytes(bytes));
        assert!(result.is_ok(), "deserializer should never panic");
        assert!(
            result.expect("checked above").is_err(),
            "malformed input must be rejected"
        );
    }

    fn serialized_label_len(bytes: &[u8]) -> usize {
        let encoded = u64::from_be_bytes(
            bytes[u64::SIZE..2 * u64::SIZE]
                .try_into()
                .expect("header is complete"),
        );
        encoded as usize
    }

    #[test]
    fn prover_rebuilds_quotient_cache_after_checked_round_trip() {
        let mut setup_rng = StdRng::seed_from_u64(47);
        let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<MinimalCircuit>(&pp, b"p1.4-3")
            .expect("circuit should compile");

        let bytes = prover.to_bytes();
        let decoded = Prover::try_from_bytes(&bytes)
            .expect("checked prover bytes should decode");

        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(decoded.domain, prover.domain);
        assert_eq!(decoded.quotient_domain, prover.quotient_domain);
        assert_eq!(
            decoded.vanishing_coset_inverses,
            prover.vanishing_coset_inverses
        );
        assert_eq!(decoded.vanishing_coset_inverses.len(), 8);

        for (i, evaluation) in
            decoded.prover_key.v_h_coset_8n().evals.iter().enumerate()
        {
            assert_eq!(
                decoded.vanishing_coset_inverses[i & 7],
                evaluation.invert().unwrap()
            );
        }

        let mut original_rng = StdRng::seed_from_u64(48);
        let mut decoded_rng = StdRng::seed_from_u64(48);
        let original_proof = prover
            .prove(&mut original_rng, &MinimalCircuit)
            .expect("compiled prover should prove");
        let decoded_proof = decoded
            .prove(&mut decoded_rng, &MinimalCircuit)
            .expect("decoded prover should prove");
        assert_eq!(decoded_proof, original_proof);
    }

    #[test]
    fn prover_rejects_public_inputs_moved_from_compiled_rows() {
        let mut setup_rng = StdRng::seed_from_u64(50);
        let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<PublicInputRows>(&pp, b"pi-rows")
            .expect("circuit should compile");
        let compiled_row = Composer::initialized().constraints();

        for value in [BlsScalar::zero(), BlsScalar::one()] {
            let circuit = PublicInputRows {
                rows: [false, true],
                value,
            };
            let mut rng = StdRng::seed_from_u64(51);
            assert_eq!(
                prover.prove(&mut rng, &circuit),
                Err(Error::PublicInputNotFound {
                    index: compiled_row
                })
            );
        }
    }

    #[test]
    fn decoded_prover_preserves_public_input_rows() {
        let mut setup_rng = StdRng::seed_from_u64(52);
        let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<PublicInputRows>(&pp, b"pi-rows")
            .expect("circuit should compile");
        let bytes = prover.to_bytes();
        let decoded = Prover::try_from_bytes(&bytes)
            .expect("serialized prover should decode");
        assert_eq!(decoded.to_bytes(), bytes);

        let moved = PublicInputRows {
            rows: [false, true],
            value: BlsScalar::one(),
        };
        let mut rng = StdRng::seed_from_u64(53);
        assert!(matches!(
            decoded.prove(&mut rng, &moved),
            Err(Error::PublicInputNotFound { .. })
        ));
    }

    #[test]
    fn prover_rejects_public_input_count_mismatch() {
        let mut setup_rng = StdRng::seed_from_u64(54);
        let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<PublicInputRows>(&pp, b"pi-rows")
            .expect("circuit should compile");

        for (rows, provided) in [([false, false], 0), ([true, true], 2)] {
            let circuit = PublicInputRows {
                rows,
                value: BlsScalar::one(),
            };
            let mut rng = StdRng::seed_from_u64(55);
            assert_eq!(
                prover.prove(&mut rng, &circuit),
                Err(Error::InconsistentPublicInputsLen {
                    expected: 1,
                    provided,
                })
            );
        }
    }

    #[test]
    fn prover_serialization_requires_valid_public_input_layout() {
        let mut setup_rng = StdRng::seed_from_u64(56);
        let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<PublicInputRows>(&pp, b"pi-rows")
            .expect("circuit should compile");

        let mut legacy = prover.to_bytes();
        legacy[..u64::SIZE].copy_from_slice(&0u64.to_be_bytes());
        assert_deserialization_error_without_panic(&legacy);

        let mut out_of_range = prover.to_bytes();
        let last = out_of_range.len() - u64::SIZE;
        out_of_range[last..]
            .copy_from_slice(&(prover.constraints as u64).to_be_bytes());
        assert_deserialization_error_without_panic(&out_of_range);

        let mut trailing = prover.to_bytes();
        trailing.push(0);
        assert_deserialization_error_without_panic(&trailing);
    }

    #[test]
    fn new_prover_format_is_rejected_by_old_32_bit_header_logic() {
        let mut setup_rng = StdRng::seed_from_u64(57);
        let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<PublicInputRows>(&pp, b"pi-rows")
            .expect("circuit should compile");
        let bytes = prover.to_bytes();

        // The previous decoder interpreted the first six words as lengths
        // and used truncating u64-to-usize casts. Simulate that logic with
        // u32 so this regression is exercised on every CI target.
        let old_label_len = u64::from_be_bytes(
            bytes[..u64::SIZE].try_into().expect("header is complete"),
        ) as u32;
        let old_prover_key_len = u64::from_be_bytes(
            bytes[u64::SIZE..2 * u64::SIZE]
                .try_into()
                .expect("header is complete"),
        ) as u32;

        assert_eq!(old_label_len, u32::MAX);
        assert!(old_label_len.checked_add(old_prover_key_len).is_none());
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn prover_rejects_header_lengths_that_do_not_fit_usize() {
        let mut bytes = vec![0u8; 56];
        bytes[..u64::SIZE]
            .copy_from_slice(&super::PROVER_FORMAT_V2_MAGIC.to_be_bytes());
        bytes[u64::SIZE..2 * u64::SIZE]
            .copy_from_slice(&(u32::MAX as u64 + 1).to_be_bytes());

        assert_deserialization_error_without_panic(&bytes);
    }

    #[test]
    fn prover_rejects_malformed_derived_cache_inputs() {
        let mut setup_rng = StdRng::seed_from_u64(49);
        let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<MinimalCircuit>(&pp, b"p1.4-4")
            .expect("circuit should compile");

        let rebuild = |prover_key, size, constraints| {
            Prover::new(
                prover.label.clone(),
                prover_key,
                prover.commit_key.clone(),
                prover.verifier_key,
                size,
                constraints,
                prover.public_input_indexes.clone(),
            )
        };
        let assert_invalid_data = |result| {
            assert!(matches!(
                result,
                Err(Error::BytesError(dusk_bytes::Error::InvalidData))
            ));
        };

        let mut short_evaluations = prover.prover_key.clone();
        short_evaluations.v_h_coset_8n.evals.pop();
        assert_invalid_data(rebuild(
            short_evaluations,
            prover.size,
            prover.constraints,
        ));

        let mut zero_evaluation = prover.prover_key.clone();
        zero_evaluation.v_h_coset_8n.evals[0] = BlsScalar::zero();
        assert_invalid_data(rebuild(
            zero_evaluation,
            prover.size,
            prover.constraints,
        ));

        assert_invalid_data(rebuild(
            prover.prover_key.clone(),
            prover.size,
            prover.size + 1,
        ));
    }

    #[test]
    fn prover_try_from_bytes_rejects_malformed_commit_key_without_panicking() {
        let mut rng = StdRng::seed_from_u64(42);
        let pp = PublicParameters::setup(1 << 10, &mut rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<MinimalCircuit>(&pp, b"p1.4-3")
            .expect("circuit should compile");

        let mut bytes = prover.to_bytes();
        bytes[24..32].copy_from_slice(&(0u64).to_be_bytes()); // commit-key length

        assert_deserialization_error_without_panic(&bytes);
    }

    #[test]
    fn prover_try_from_bytes_rejects_empty_inner_commit_key() {
        let mut rng = StdRng::seed_from_u64(44);
        let pp = PublicParameters::setup(1 << 10, &mut rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<MinimalCircuit>(&pp, b"p1.4-3")
            .expect("circuit should compile");
        let bytes = prover.to_bytes();

        let label_len = serialized_label_len(&bytes);
        let prover_key_len = u64::from_be_bytes(
            bytes[2 * u64::SIZE..3 * u64::SIZE]
                .try_into()
                .expect("header is complete"),
        ) as usize;
        let commit_key_len = u64::from_be_bytes(
            bytes[3 * u64::SIZE..4 * u64::SIZE]
                .try_into()
                .expect("header is complete"),
        ) as usize;
        let commit_key_offset = 7 * u64::SIZE + label_len + prover_key_len;
        let verifier_key_offset = commit_key_offset + commit_key_len;

        let mut malformed = bytes[..commit_key_offset].to_vec();
        malformed.extend_from_slice(&0u64.to_le_bytes());
        malformed.extend_from_slice(&bytes[verifier_key_offset..]);
        malformed[3 * u64::SIZE..4 * u64::SIZE]
            .copy_from_slice(&(u64::SIZE as u64).to_be_bytes());

        assert_deserialization_error_without_panic(&malformed);
    }

    #[test]
    fn prover_try_from_bytes_rejects_malformed_inner_key_without_panicking() {
        let mut rng = StdRng::seed_from_u64(43);
        let pp = PublicParameters::setup(1 << 10, &mut rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<MinimalCircuit>(&pp, b"p1.4-3")
            .expect("circuit should compile");
        let bytes = prover.to_bytes();

        let label_len = serialized_label_len(&bytes);
        let prover_key_offset = 7 * u64::SIZE + label_len;
        let evaluations_size_offset = prover_key_offset + u64::SIZE;
        let first_polynomial_len_offset = prover_key_offset + 2 * u64::SIZE;

        let mut zero_size = bytes.clone();
        zero_size[5 * u64::SIZE..6 * u64::SIZE]
            .copy_from_slice(&0u64.to_bytes());
        assert_deserialization_error_without_panic(&zero_size);

        let size = u64::from_slice(&bytes[5 * u64::SIZE..6 * u64::SIZE])
            .expect("serialized circuit size should decode");
        let mut mismatched_prover_key_size = bytes.clone();
        mismatched_prover_key_size[5 * u64::SIZE..6 * u64::SIZE]
            .copy_from_slice(&(size * 2).to_bytes());
        mismatched_prover_key_size[6 * u64::SIZE..7 * u64::SIZE]
            .copy_from_slice(&(size + 1).to_bytes());
        assert_deserialization_error_without_panic(&mismatched_prover_key_size);

        let mut oversized_evaluations = bytes.clone();
        oversized_evaluations
            [evaluations_size_offset..evaluations_size_offset + u64::SIZE]
            .copy_from_slice(&u64::MAX.to_bytes());
        assert_deserialization_error_without_panic(&oversized_evaluations);

        let mut undersized_evaluations = bytes.clone();
        undersized_evaluations
            [evaluations_size_offset..evaluations_size_offset + u64::SIZE]
            .copy_from_slice(&0u64.to_bytes());
        assert_deserialization_error_without_panic(&undersized_evaluations);

        let mut oversized_polynomial = bytes.clone();
        oversized_polynomial[first_polynomial_len_offset
            ..first_polynomial_len_offset + u64::SIZE]
            .copy_from_slice(&u64::MAX.to_bytes());
        assert_deserialization_error_without_panic(&oversized_polynomial);

        let polynomial_len = u64::from_slice(
            &bytes[first_polynomial_len_offset
                ..first_polynomial_len_offset + u64::SIZE],
        )
        .expect("serialized polynomial length should decode")
            as usize;
        let first_evaluations_offset = first_polynomial_len_offset
            + u64::SIZE
            + polynomial_len * BlsScalar::SIZE;
        let mut malformed_domain = bytes;
        malformed_domain[first_evaluations_offset + u64::SIZE
            ..first_evaluations_offset + u64::SIZE + u32::SIZE]
            .copy_from_slice(&0u32.to_bytes());
        assert_deserialization_error_without_panic(&malformed_domain);
    }

    #[test]
    fn prover_try_from_bytes_rejects_incorrect_nonzero_linear_evaluation() {
        let mut rng = StdRng::seed_from_u64(46);
        let pp = PublicParameters::setup(1 << 10, &mut rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<MinimalCircuit>(&pp, b"p1.4-3")
            .expect("circuit should compile");
        let mut bytes = prover.to_bytes();

        let label_len = serialized_label_len(&bytes);
        let prover_key_len = u64::from_be_bytes(
            bytes[2 * u64::SIZE..3 * u64::SIZE]
                .try_into()
                .expect("header is complete"),
        ) as usize;
        let prover_key_offset = 7 * u64::SIZE + label_len;
        let evaluations_size = u64::from_slice(
            &bytes[prover_key_offset + u64::SIZE
                ..prover_key_offset + 2 * u64::SIZE],
        )
        .expect("serialized evaluation size should decode")
            as usize;
        let first_linear_evaluation = prover_key_offset + prover_key_len
            - 2 * evaluations_size
            + EvaluationDomain::SIZE;
        let second_linear_evaluation =
            first_linear_evaluation + BlsScalar::SIZE;
        let replacement = bytes[second_linear_evaluation
            ..second_linear_evaluation + BlsScalar::SIZE]
            .to_vec();
        bytes[first_linear_evaluation
            ..first_linear_evaluation + BlsScalar::SIZE]
            .copy_from_slice(&replacement);

        assert_deserialization_error_without_panic(&bytes);
    }

    #[test]
    fn prover_try_from_bytes_rejects_zero_vanishing_evaluation() {
        let mut rng = StdRng::seed_from_u64(44);
        let pp = PublicParameters::setup(1 << 10, &mut rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<MinimalCircuit>(&pp, b"p1.4-3")
            .expect("circuit should compile");
        let mut bytes = prover.to_bytes();

        let label_len = serialized_label_len(&bytes);
        let prover_key_len = u64::from_be_bytes(
            bytes[2 * u64::SIZE..3 * u64::SIZE]
                .try_into()
                .expect("header is complete"),
        ) as usize;
        let prover_key_offset = 7 * u64::SIZE + label_len;
        let evaluations_size = u64::from_slice(
            &bytes[prover_key_offset + u64::SIZE
                ..prover_key_offset + 2 * u64::SIZE],
        )
        .expect("serialized evaluation size should decode")
            as usize;
        let first_vanishing_evaluation = prover_key_offset + prover_key_len
            - evaluations_size
            + EvaluationDomain::SIZE;
        bytes[first_vanishing_evaluation
            ..first_vanishing_evaluation + BlsScalar::SIZE]
            .fill(0);

        assert_deserialization_error_without_panic(&bytes);
    }

    #[test]
    fn prover_try_from_bytes_rejects_incorrect_nonzero_vanishing_evaluation() {
        let mut rng = StdRng::seed_from_u64(45);
        let pp = PublicParameters::setup(1 << 10, &mut rng)
            .expect("public parameters should build");
        let (prover, _) = Compiler::compile::<MinimalCircuit>(&pp, b"p1.4-3")
            .expect("circuit should compile");
        let mut bytes = prover.to_bytes();

        let label_len = serialized_label_len(&bytes);
        let prover_key_len = u64::from_be_bytes(
            bytes[2 * u64::SIZE..3 * u64::SIZE]
                .try_into()
                .expect("header is complete"),
        ) as usize;
        let prover_key_offset = 7 * u64::SIZE + label_len;
        let evaluations_size = u64::from_slice(
            &bytes[prover_key_offset + u64::SIZE
                ..prover_key_offset + 2 * u64::SIZE],
        )
        .expect("serialized evaluation size should decode")
            as usize;
        let first_vanishing_evaluation = prover_key_offset + prover_key_len
            - evaluations_size
            + EvaluationDomain::SIZE;
        let second_vanishing_evaluation =
            first_vanishing_evaluation + BlsScalar::SIZE;
        let replacement = bytes[second_vanishing_evaluation
            ..second_vanishing_evaluation + BlsScalar::SIZE]
            .to_vec();
        bytes[first_vanishing_evaluation
            ..first_vanishing_evaluation + BlsScalar::SIZE]
            .copy_from_slice(&replacement);

        assert_deserialization_error_without_panic(&bytes);
    }

    #[test]
    fn precomputed_wire_blinders_preserve_rng_order() {
        let domain = EvaluationDomain::new(8).unwrap();
        let witnesses: Vec<_> = (0..domain.size())
            .map(|i| BlsScalar::from(i as u64))
            .collect();
        let mut sequential_rng = StdRng::seed_from_u64(0x51_6d_a);
        let mut precomputed_rng = sequential_rng.clone();

        let sequential = [
            Prover::blind_poly(&mut sequential_rng, &witnesses, 1, &domain),
            Prover::blind_poly(&mut sequential_rng, &witnesses, 1, &domain),
            Prover::blind_poly(&mut sequential_rng, &witnesses, 1, &domain),
            Prover::blind_poly(&mut sequential_rng, &witnesses, 1, &domain),
        ];
        let blinders = Prover::sample_wire_blinders(&mut precomputed_rng);
        let precomputed = blinders.map(|blinders| {
            Prover::blind_poly_with_blinders(&witnesses, &blinders, &domain)
        });

        assert_eq!(precomputed, sequential);
    }

    #[test]
    fn deterministic_v3_proof_matches_base_digest() {
        let mut setup_rng = StdRng::seed_from_u64(0x9235_e700);
        let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
            .expect("public parameters should build");
        let (prover, _) =
            Compiler::compile::<MinimalCircuit>(&pp, b"proof-compatibility")
                .expect("circuit should compile");
        let mut proving_rng = StdRng::seed_from_u64(0x9235_e701);
        let (proof, _) = prover
            .prove_with_version(
                &mut proving_rng,
                &MinimalCircuit,
                crate::compiler::PlonkVersion::V3,
            )
            .expect("V3 proof should build");

        // Generated at the PR's base revision, 768cf849. This pins proof
        // bytes, including transcript challenges and proving RNG order.
        let expected = [
            0xe8, 0x56, 0x4e, 0xc2, 0x2d, 0x8c, 0xc0, 0xba, 0x60, 0x36, 0x26,
            0x02, 0x5d, 0xa3, 0x75, 0x50, 0x77, 0xaa, 0xf0, 0x32, 0x32, 0x61,
            0x90, 0x8d, 0xab, 0x68, 0xd6, 0x94, 0x73, 0x6f, 0xc2, 0x73, 0xd3,
            0x1e, 0x25, 0x6c, 0xbd, 0x3a, 0x6a, 0x21, 0xe7, 0xad, 0xe6, 0x31,
            0x91, 0xac, 0x5c, 0x9d, 0x44, 0xa1, 0x13, 0xac, 0x49, 0x89, 0xa5,
            0x2e, 0x4b, 0xe3, 0xab, 0xeb, 0x1d, 0x33, 0x32, 0x37,
        ];
        let digest = blake2b_simd::blake2b(&proof.to_bytes());

        assert_eq!(digest.as_array(), &expected);
    }

    #[test]
    fn prover_roundtrip_reconstructs_sigma_evaluations() {
        let mut rng = StdRng::seed_from_u64(47);
        let pp = PublicParameters::setup(1 << 10, &mut rng)
            .expect("public parameters should build");
        let (prover, verifier) =
            Compiler::compile::<MinimalCircuit>(&pp, b"sigma-cache")
                .expect("circuit should compile");
        let bytes = prover.to_bytes();

        let decoded = Prover::try_from_bytes(&bytes)
            .expect("serialized prover should decode");
        assert_eq!(decoded.sigma_evaluations, prover.sigma_evaluations);
        assert_eq!(decoded.to_bytes(), bytes);

        let (proof, public_inputs) = decoded
            .prove(&mut rng, &MinimalCircuit)
            .expect("decoded prover should prove");
        verifier
            .verify(&proof, &public_inputs)
            .expect("proof from decoded prover should verify");
    }

    #[test]
    fn prover_try_from_bytes_rejects_overflow_lengths_without_panicking() {
        let mut bytes = Vec::with_capacity(56);
        bytes.extend_from_slice(&super::PROVER_FORMAT_V2_MAGIC.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes()); // label_len
        bytes.extend_from_slice(&u64::MAX.to_be_bytes()); // prover_key_len
        bytes.extend_from_slice(&u64::MAX.to_be_bytes()); // commit_key_len
        bytes.extend_from_slice(&u64::MAX.to_be_bytes()); // verifier_key_len
        bytes.extend_from_slice(&0u64.to_be_bytes()); // size
        bytes.extend_from_slice(&0u64.to_be_bytes()); // constraints

        let result =
            std::panic::catch_unwind(|| Prover::try_from_bytes(&bytes));
        assert!(result.is_ok(), "deserializer should never panic");
        assert!(matches!(
            result.expect("checked above"),
            Err(Error::NotEnoughBytes)
        ));
    }
}
