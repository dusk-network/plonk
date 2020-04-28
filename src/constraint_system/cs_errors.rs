//! Errors related to the Constraint system

use failure::Error;

/// Represents an error on the Circuit preprocessing stage.
#[derive(Fail, Debug)]
pub enum PreProcessingError {
    /// This error occurs when an error triggers during the preprocessing
    /// stage.
    #[fail(display = "the length of the wires it's not the same")]
    MissmatchedPolyLen,
}

#[derive(Debug, Fail)]
#[fail(display = "Proving error")]
/// Represents an error on the Proving stage.
pub struct ProvingError(#[fail(cause)] Error);
