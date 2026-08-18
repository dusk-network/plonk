// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
use merlin::Transcript;

use super::PlonkVersion;
use crate::commitment_scheme::OpeningKey;
use crate::error::Error;
use crate::fft::EvaluationDomain;
use crate::proof_system::{Proof, VerifierKey};
use crate::transcript::TranscriptProtocol;
/// Verify proofs of a given circuit
pub struct Verifier {
    label: Vec<u8>,
    verifier_key: VerifierKey,
    opening_key: OpeningKey,
    public_input_indexes: Vec<usize>,
    public_input_roots: Vec<BlsScalar>,
    domain: EvaluationDomain,
    transcript: Transcript,
    size: usize,
    constraints: usize,
}

impl Verifier {
    pub(crate) fn new(
        label: Vec<u8>,
        verifier_key: VerifierKey,
        opening_key: OpeningKey,
        public_input_indexes: Vec<usize>,
        size: usize,
        constraints: usize,
    ) -> Result<Self, Error> {
        let domain = EvaluationDomain::new(verifier_key.n)?;
        let public_input_roots = public_input_indexes
            .iter()
            .map(|index| domain.group_gen_inv.pow(&[*index as u64, 0, 0, 0]))
            .collect();
        let transcript =
            Transcript::base(label.as_slice(), &verifier_key, constraints);

        Ok(Self {
            label,
            verifier_key,
            opening_key,
            public_input_indexes,
            public_input_roots,
            domain,
            transcript,
            size,
            constraints,
        })
    }

    fn prepare_serialize(
        &self,
    ) -> (usize, [u8; VerifierKey::SIZE], [u8; OpeningKey::SIZE]) {
        let verifier_key = self.verifier_key.to_bytes();
        let opening_key = self.opening_key.to_bytes();

        let label_len = self.label.len();
        let verifier_key_len = verifier_key.len();
        let opening_key_len = opening_key.len();
        let public_input_indexes_len = self.public_input_indexes.len() * 8;

        let size = 48
            + label_len
            + verifier_key_len
            + opening_key_len
            + public_input_indexes_len;

        (size, verifier_key, opening_key)
    }

    /// Serialized size in bytes
    pub fn serialized_size(&self) -> usize {
        self.prepare_serialize().0
    }

    /// Serialize the verifier into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let (size, verifier_key, opening_key) = self.prepare_serialize();
        let mut bytes = Vec::with_capacity(size);

        let label_len = self.label.len() as u64;
        let verifier_key_len = verifier_key.len() as u64;
        let opening_key_len = opening_key.len() as u64;
        let public_input_indexes_len = self.public_input_indexes.len() as u64;
        let size = self.size as u64;
        let constraints = self.constraints as u64;

        bytes.extend(label_len.to_be_bytes());
        bytes.extend(verifier_key_len.to_be_bytes());
        bytes.extend(opening_key_len.to_be_bytes());
        bytes.extend(public_input_indexes_len.to_be_bytes());
        bytes.extend(size.to_be_bytes());
        bytes.extend(constraints.to_be_bytes());

        bytes.extend(self.label.as_slice());
        bytes.extend(verifier_key);
        bytes.extend(opening_key);

        self.public_input_indexes
            .iter()
            .map(|i| *i as u64)
            .map(u64::to_be_bytes)
            .for_each(|i| bytes.extend(i));

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

        let verifier_key_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let verifier_key_len = u64::from_be_bytes(verifier_key_len) as usize;
        bytes = &bytes[8..];

        let opening_key_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let opening_key_len = u64::from_be_bytes(opening_key_len) as usize;
        bytes = &bytes[8..];

        let public_input_indexes_len =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let public_input_indexes_len =
            u64::from_be_bytes(public_input_indexes_len) as usize;
        bytes = &bytes[8..];
        let public_input_indexes_bytes_len = public_input_indexes_len
            .checked_mul(8)
            .ok_or(Error::NotEnoughBytes)?;

        let size = <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let size = u64::from_be_bytes(size) as usize;
        bytes = &bytes[8..];

        let constraints =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let constraints = u64::from_be_bytes(constraints) as usize;
        bytes = &bytes[8..];

        let required_len = label_len
            .checked_add(verifier_key_len)
            .and_then(|len| len.checked_add(opening_key_len))
            .and_then(|len| len.checked_add(public_input_indexes_bytes_len))
            .ok_or(Error::NotEnoughBytes)?;

        if bytes.len() < required_len {
            return Err(Error::NotEnoughBytes);
        }

        let label = &bytes[..label_len];
        bytes = &bytes[label_len..];

        let verifier_key = &bytes[..verifier_key_len];
        bytes = &bytes[verifier_key_len..];

        let opening_key = &bytes[..opening_key_len];
        bytes = &bytes[opening_key_len..];

        let public_input_indexes = &bytes[..public_input_indexes_bytes_len];

        let label = label.to_vec();
        let verifier_key = VerifierKey::from_slice(verifier_key)?;
        let opening_key = OpeningKey::from_slice(opening_key)?;
        let public_input_indexes = public_input_indexes
            .chunks_exact(8)
            .map(|c| <[u8; 8]>::try_from(c).expect("checked len"))
            .map(u64::from_be_bytes)
            .map(|n| n as usize)
            .collect();

        Self::new(
            label,
            verifier_key,
            opening_key,
            public_input_indexes,
            size,
            constraints,
        )
    }

    /// Verify a generated proof using the current (latest) verification
    /// behavior.
    pub fn verify(
        &self,
        proof: &Proof,
        public_inputs: &[BlsScalar],
    ) -> Result<(), Error> {
        self.verify_with_version(proof, public_inputs, PlonkVersion::current())
    }

    /// Verify a generated proof using an explicitly selected version.
    pub fn verify_with_version(
        &self,
        proof: &Proof,
        public_inputs: &[BlsScalar],
        version: PlonkVersion,
    ) -> Result<(), Error> {
        if public_inputs.len() != self.public_input_indexes.len() {
            return Err(Error::InconsistentPublicInputsLen {
                expected: self.public_input_indexes.len(),
                provided: public_inputs.len(),
            });
        }

        let mut transcript = self.transcript_for_version(version);

        public_inputs
            .iter()
            .for_each(|pi| transcript.append_scalar(b"pi", pi));

        match version {
            PlonkVersion::V1 => proof.verify_legacy(
                &self.verifier_key,
                &mut transcript,
                &self.opening_key,
                &self.domain,
                &self.public_input_roots,
                public_inputs,
            ),
            PlonkVersion::V2 | PlonkVersion::V3 => proof.verify(
                &self.verifier_key,
                &mut transcript,
                &self.opening_key,
                &self.domain,
                &self.public_input_roots,
                public_inputs,
            ),
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
}

#[cfg(test)]
mod tests {
    use dusk_bls12_381::BlsScalar;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;
    use crate::prelude::{Circuit, Compiler, Composer, PublicParameters};

    #[derive(Default)]
    struct MinimalCircuit;

    impl Circuit for MinimalCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let witness = composer.append_witness(BlsScalar::from(7u64));
            composer.assert_equal_constant(
                witness,
                BlsScalar::from(7u64),
                None,
            );
            Ok(())
        }
    }

    #[test]
    fn verifier_try_from_bytes_rejects_overflow_lengths_without_panicking() {
        let mut bytes = Vec::with_capacity(48);
        bytes.extend_from_slice(&0u64.to_be_bytes()); // label_len
        bytes.extend_from_slice(&0u64.to_be_bytes()); // verifier_key_len
        bytes.extend_from_slice(&0u64.to_be_bytes()); // opening_key_len
        bytes.extend_from_slice(&u64::MAX.to_be_bytes()); // public_input_indexes_len
        bytes.extend_from_slice(&0u64.to_be_bytes()); // size
        bytes.extend_from_slice(&0u64.to_be_bytes()); // constraints

        let result =
            std::panic::catch_unwind(|| Verifier::try_from_bytes(&bytes));
        assert!(
            result.is_ok(),
            "try_from_bytes panicked on overflow lengths"
        );
        assert!(matches!(result.unwrap(), Err(Error::NotEnoughBytes)));
    }

    #[test]
    fn verifier_try_from_bytes_rejects_oversized_domain_without_panicking() {
        let mut rng = StdRng::seed_from_u64(42);
        let pp = PublicParameters::setup(1 << 5, &mut rng)
            .expect("public parameters should build");
        let (_, verifier) =
            Compiler::compile::<MinimalCircuit>(&pp, b"oversized-domain")
                .expect("circuit should compile");

        let mut bytes = verifier.to_bytes();
        let label_len = u64::from_be_bytes(
            bytes[..u64::SIZE].try_into().expect("header is complete"),
        ) as usize;
        let verifier_key_offset = 48 + label_len;
        bytes[verifier_key_offset..verifier_key_offset + u64::SIZE].fill(0xff);

        let result =
            std::panic::catch_unwind(|| Verifier::try_from_bytes(&bytes));
        assert!(result.is_ok(), "deserializer should never panic");
        assert!(matches!(
            result.expect("checked above"),
            Err(Error::InvalidEvalDomainSize { .. })
        ));
    }
}
