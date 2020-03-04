//! FFT module contains the encoding for the multiplication
//! of polynomials over select finite fields.
pub(crate) mod constants;
pub(crate) mod domain;
pub(crate) mod evaluations;
pub(crate) mod polynomial;

pub use domain::EvaluationDomain;
pub use evaluations::Evaluations;
pub use polynomial::Polynomial;
