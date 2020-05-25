pub mod arithmetic;
pub mod logic;
pub mod permutation;
pub mod range;

use crate::fft::Evaluations;
use crate::transcript::TranscriptProtocol;
use merlin::Transcript;
/// PLONK circuit proving key
#[derive(Debug)]
pub struct ProverKey {
    /// ProverKey for arithmetic gate
    pub arithmetic: arithmetic::ProverKey,
    /// ProverKey for logic gate
    pub logic: logic::ProverKey,
    /// ProverKey for range gate
    pub range: range::ProverKey,
    /// ProverKey for permutation checks
    pub permutation: permutation::ProverKey,
    // Pre-processes the 4n Evaluations for the vanishing polynomial, so they do not
    // need to be computed at the proving stage.
    // Note: With this, we can combine all parts of the quotient polynomial in their evaluation phase and
    // divide by the quotient polynomial without having to perform IFFT
    pub(crate) v_h_coset_4n: Evaluations,
}

/// PLONK circuit verification key
#[derive(Debug)]
pub struct VerifierKey {
    /// Circuit size
    pub n: usize,
    /// VerifierKey for arithmetic gates
    pub arithmetic: arithmetic::VerifierKey,
    /// VerifierKey for logic gates
    pub logic: logic::VerifierKey,
    /// VerifierKey for range gates
    pub range: range::VerifierKey,
    /// VerifierKey for permutation checks
    pub permutation: permutation::VerifierKey,
}

impl VerifierKey {
    /// Adds the circuit description to the transcript
    pub(crate) fn seed_transcript(&self, transcript: &mut Transcript) {
        transcript.append_commitment(b"q_m", &self.arithmetic.q_m);
        transcript.append_commitment(b"q_l", &self.arithmetic.q_l);
        transcript.append_commitment(b"q_r", &self.arithmetic.q_r);
        transcript.append_commitment(b"q_o", &self.arithmetic.q_o);
        transcript.append_commitment(b"q_c", &self.arithmetic.q_c);
        transcript.append_commitment(b"q_4", &self.arithmetic.q_4);
        transcript.append_commitment(b"q_arith", &self.arithmetic.q_arith);
        transcript.append_commitment(b"q_range", &self.range.q_range);
        transcript.append_commitment(b"q_logic", &self.logic.q_logic);

        transcript.append_commitment(b"left_sigma", &self.permutation.left_sigma);
        transcript.append_commitment(b"right_sigma", &self.permutation.right_sigma);
        transcript.append_commitment(b"out_sigma", &self.permutation.out_sigma);
        transcript.append_commitment(b"fourth_sigma", &self.permutation.fourth_sigma);

        // Append circuit size to transcript
        transcript.circuit_domain_sep(self.n as u64);
    }
}

impl ProverKey {
    pub(crate) fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}
