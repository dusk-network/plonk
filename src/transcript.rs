// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This is an extension over the [Merlin Transcript](Transcript)
//! which adds a few extra functionalities.

use core::mem;

use dusk_bytes::Serializable;
use merlin::Transcript;
use zero_bls12_381::Fr as BlsScalar;

use crate::commitment_scheme::Commitment;
use crate::proof_system::VerifierKey;

/// Transcript adds an abstraction over the Merlin transcript
/// For convenience
pub(crate) trait TranscriptProtocol {
    /// Append a `commitment` with the given `label`.
    fn append_commitment(&mut self, label: &'static [u8], comm: &Commitment);

    /// Append a `BlsScalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], s: &BlsScalar);

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> BlsScalar;

    /// Append domain separator for the circuit size.
    fn circuit_domain_sep(&mut self, n: u64);

    /// Create a new instance of the base transcript of the protocol
    fn base(
        label: &[u8],
        verifier_key: &VerifierKey,
        constraints: usize,
    ) -> Self;
}

impl TranscriptProtocol for Transcript {
    fn append_commitment(&mut self, label: &'static [u8], comm: &Commitment) {
        self.append_message(label, &comm.0.to_bytes());
    }

    fn append_scalar(&mut self, label: &'static [u8], s: &BlsScalar) {
        self.append_message(label, &s.to_bytes())
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> BlsScalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        BlsScalar::from_bytes_wide(&buf)
    }

    fn circuit_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"circuit_size");
        self.append_u64(b"n", n);
    }

    fn base(
        label: &[u8],
        verifier_key: &VerifierKey,
        constraints: usize,
    ) -> Self {
        // Transcript can't be serialized/deserialized. One alternative is to
        // fork merlin and implement these functionalities, so we can use custom
        // transcripts for provers and verifiers. However, we don't have a use
        // case for this feature in Dusk.

        // Safety: static lifetime is a pointless requirement from merlin that
        // doesn't add any security but instead restricts a lot the
        // serialization and deserialization of transcripts
        let label = unsafe { mem::transmute(label) };

        let mut transcript = Transcript::new(label);

        transcript.circuit_domain_sep(constraints as u64);

        verifier_key.seed_transcript(&mut transcript);

        transcript
    }
}
