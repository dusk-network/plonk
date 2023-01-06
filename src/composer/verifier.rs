// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use core::marker::PhantomData;

use dusk_bytes::{DeserializableSlice, Serializable};
use merlin::Transcript;
use zero_bls12_381::Fr as BlsScalar;

use crate::commitment_scheme::OpeningKey;
use crate::error::Error;
use crate::proof_system::{Proof, VerifierKey};
use crate::transcript::TranscriptProtocol;

use super::Builder;

/// Verify proofs of a given circuit
pub struct Verifier<C> {
    label: Vec<u8>,
    verifier_key: VerifierKey,
    opening_key: OpeningKey,
    public_input_indexes: Vec<usize>,
    transcript: Transcript,
    size: usize,
    constraints: usize,
    circuit: PhantomData<C>,
}

impl<C> Verifier<C> {
    pub(crate) fn new(
        label: Vec<u8>,
        verifier_key: VerifierKey,
        opening_key: OpeningKey,
        public_input_indexes: Vec<usize>,
        size: usize,
        constraints: usize,
    ) -> Self {
        let transcript =
            Transcript::base(label.as_slice(), &verifier_key, constraints);

        Self {
            label,
            verifier_key,
            opening_key,
            public_input_indexes,
            transcript,
            size,
            constraints,
            circuit: PhantomData,
        }
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

        let size = <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let size = u64::from_be_bytes(size) as usize;
        bytes = &bytes[8..];

        let constraints =
            <[u8; 8]>::try_from(&bytes[..8]).expect("checked len");
        let constraints = u64::from_be_bytes(constraints) as usize;
        bytes = &bytes[8..];

        if bytes.len()
            < label_len
                + verifier_key_len
                + opening_key_len
                + public_input_indexes_len * 8
        {
            return Err(Error::NotEnoughBytes);
        }

        let label = &bytes[..label_len];
        bytes = &bytes[label_len..];

        let verifier_key = &bytes[..verifier_key_len];
        bytes = &bytes[verifier_key_len..];

        let opening_key = &bytes[..opening_key_len];
        bytes = &bytes[opening_key_len..];

        let public_input_indexes = &bytes[..public_input_indexes_len * 8];

        let label = label.to_vec();
        let verifier_key = VerifierKey::from_slice(verifier_key)?;
        let opening_key = OpeningKey::from_slice(opening_key)?;
        let public_input_indexes = public_input_indexes
            .chunks_exact(8)
            .map(|c| <[u8; 8]>::try_from(c).expect("checked len"))
            .map(u64::from_be_bytes)
            .map(|n| n as usize)
            .collect();

        Ok(Self::new(
            label,
            verifier_key,
            opening_key,
            public_input_indexes,
            size,
            constraints,
        ))
    }

    /// Verify a generated proof
    pub fn verify(
        &self,
        proof: &Proof,
        public_inputs: &[BlsScalar],
    ) -> Result<(), Error> {
        if public_inputs.len() != self.public_input_indexes.len() {
            return Err(Error::InconsistentPublicInputsLen {
                expected: self.public_input_indexes.len(),
                provided: public_inputs.len(),
            });
        }

        let mut transcript = self.transcript.clone();

        public_inputs
            .iter()
            .for_each(|pi| transcript.append_scalar(b"pi", pi));

        let dense_public_inputs = Builder::dense_public_inputs(
            &self.public_input_indexes,
            public_inputs,
            self.size,
        );

        proof.verify(
            &self.verifier_key,
            &mut transcript,
            &self.opening_key,
            &dense_public_inputs,
        )
    }
}
