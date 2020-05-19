use crate::fft::Evaluations;
use crate::proof_system::widget::{ProverKey, VerifierKey};
use crate::transcript::TranscriptProtocol;
use merlin::Transcript;

/// `PreProcessedCircuit` is a data structure that holds the commitments to
/// the selector and sigma polynomials.
///
/// By doing this, we can see the `PreProcessedCircuit` as a "circuit-shape descriptor"
/// since it only stores the commitments that describe the operations that we will perform
/// innside the circuit.
#[derive(Debug)]
pub struct PreProcessedCircuit {
    /// The number of gates in the circuit
    pub n: usize,
    /// Prover Keys for a TurboPlonk circuit
    pub prover_key: ProverKey,
    /// Verifier Keys for a TurboPlonk circuit
    pub verifier_key: VerifierKey,

    // Pre-processes the 4n Evaluations for the vanishing polynomial, so they do not
    // need to be computed at the proving stage.
    // Note: With this, we can combine all parts of the quotient polynomial in their evaluation phase and
    // divide by the quotient polynomial without having to perform IFFT
    pub(crate) v_h_coset_4n: Evaluations,
}

impl PreProcessedCircuit {
    pub(crate) fn seed_transcript(&self, transcript: &mut Transcript) {
        transcript.append_commitment(b"q_m", &self.verifier_key.arithmetic.q_m);
        transcript.append_commitment(b"q_l", &self.verifier_key.arithmetic.q_l);
        transcript.append_commitment(b"q_r", &self.verifier_key.arithmetic.q_r);
        transcript.append_commitment(b"q_o", &self.verifier_key.arithmetic.q_o);
        transcript.append_commitment(b"q_c", &self.verifier_key.arithmetic.q_c);
        transcript.append_commitment(b"q_4", &self.verifier_key.arithmetic.q_4);
        transcript.append_commitment(b"q_arith", &self.verifier_key.arithmetic.q_arith);
        transcript.append_commitment(b"q_range", &self.verifier_key.range.q_range);
        transcript.append_commitment(b"q_logic", &self.verifier_key.logic.q_logic);

        transcript.append_commitment(b"left_sigma", &self.verifier_key.permutation.left_sigma);
        transcript.append_commitment(b"right_sigma", &self.verifier_key.permutation.right_sigma);
        transcript.append_commitment(b"out_sigma", &self.verifier_key.permutation.out_sigma);
        transcript.append_commitment(b"fourth_sigma", &self.verifier_key.permutation.fourth_sigma);

        // Append circuit size to transcript
        transcript.circuit_domain_sep(self.n as u64);
    }
}

impl PreProcessedCircuit {
    pub(crate) fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}
