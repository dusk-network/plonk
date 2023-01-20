// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use core::marker::PhantomData;

use merlin::Transcript;
use zero_bls12_381::Fr as BlsScalar;

use crate::commitment_scheme::OpeningKey;
use crate::error::Error;
use crate::proof_system::{Proof, VerifierKey};
use crate::transcript::TranscriptProtocol;

use super::Builder;

/// Verify proofs of a given circuit
pub struct Verifier<C> {
    verifier_key: VerifierKey,
    opening_key: OpeningKey,
    public_input_indexes: Vec<usize>,
    transcript: Transcript,
    size: usize,
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
            verifier_key,
            opening_key,
            public_input_indexes,
            transcript,
            size,
            circuit: PhantomData,
        }
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
