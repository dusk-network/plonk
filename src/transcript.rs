// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This is an extension over the [Merlin Transcript](Transcript)
//! which adds a few extra functionalities.
use crate::commitment_scheme::kzg10::Commitment;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use merlin::Transcript;

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
}
