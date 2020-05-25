pub mod arithmetic;
pub mod logic;
pub mod permutation;
pub mod range;

use crate::fft::Evaluations;

/// PLONK circuit proving key
#[derive(Debug)]
pub struct ProverKey {
    pub arithmetic: arithmetic::ProverKey,
    pub logic: logic::ProverKey,
    pub range: range::ProverKey,
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
    pub arithmetic: arithmetic::VerifierKey,
    pub logic: logic::VerifierKey,
    pub range: range::VerifierKey,
    pub permutation: permutation::VerifierKey,
}

impl ProverKey {
    pub(crate) fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}
