//! Errors related to the Constraint system

use thiserror::Error;

/// Represents an error on the Circuit preprocessing stage.
#[derive(Error, Debug)]
pub enum PreProcessingError {
    /// This error occurs when an error triggers during the preprocessing
    /// stage.
    #[error("the length of the wires it's not the same")]
    MissmatchedPolyLen,
}
