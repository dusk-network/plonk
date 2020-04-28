//! Errors related to the proof_system module.

use failure::Error;
/// Defines all of the possible ProofError types that we could have when
/// we are working with the `proof_system` module.
#[derive(Fail, Debug)]
pub enum ProofErrors {
    /// This error occurs when the verification of a `Proof` fails.
    #[fail(display = "proof verification failed")]
    ProofVerificationError,
}

#[derive(Debug, Fail)]
#[fail(display = "proof_system module error")]
/// Represents an error triggered on any of the proof_system
/// module operations such as verification errors
pub struct ProofError(#[fail(cause)] pub(crate) Error);
