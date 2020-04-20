//! Transcript is an utility that helps to perform the
//! `Fiat-Shamir` heuristics without a direct communication
//! between `Prover` and `Verifier`.
//!
//! This is an extension over the [Merlin Transcript](merlin::Transcript)
//! which adds a few extra functionalities.
use crate::commitment_scheme::kzg10::Commitment;
use bls12_381::Scalar;
use merlin::Transcript;

/// This is an extension over the [Merlin Transcript](merlin::Transcript)
/// which adds a few extra functionalities.
pub trait TranscriptProtocol {
    /// Append a `commitment` with the given `label`.
    fn append_commitment(&mut self, label: &'static [u8], comm: &Commitment);

    /// Append a `Scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], s: &Scalar);

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;

    /// Append domain separator for the circuit size.
    fn circuit_domain_sep(&mut self, n: u64);
}

impl TranscriptProtocol for Transcript {
    fn append_commitment(&mut self, label: &'static [u8], comm: &Commitment) {
        self.append_message(label, &comm.0.to_compressed());
    }

    fn append_scalar(&mut self, label: &'static [u8], s: &Scalar) {
        self.append_message(label, &s.to_bytes())
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_wide(&buf)
    }

    fn circuit_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"circuit_size");
        self.append_u64(b"n", n);
    }
}
