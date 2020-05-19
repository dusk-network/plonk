pub mod arithmetic;
pub mod logic;
pub mod permutation;
pub mod range;

/// PLONK circuit proving key
#[derive(Debug)]
pub struct ProverKey {
    pub arithmetic: arithmetic::ProverKey,
    pub logic: logic::ProverKey,
    pub range: range::ProverKey,
    pub permutation: permutation::ProverKey,
}

/// PLONK circuit verification key
#[derive(Debug)]
pub struct VerifierKey {
    pub arithmetic: arithmetic::VerifierKey,
    pub logic: logic::VerifierKey,
    pub range: range::VerifierKey,
    pub permutation: permutation::VerifierKey,
}
