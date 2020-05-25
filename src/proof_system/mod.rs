//! proving system

pub(crate) mod linearisation_poly;
mod preprocess;

/// Represents a PLONK Proof
pub mod proof;
pub(crate) mod proof_system_errors;
/// Represents a PLONK Prover
pub mod prover;
pub(crate) mod quotient_poly;
/// Represents a PLONK Verifier
pub mod verifier;
pub(crate) mod widget;

pub use proof::Proof;
pub use prover::Prover;
pub use verifier::Verifier;
