//! FFT module contains the tools needed by the Composer backend
//! to know and use the logic behind Polynomials, and the operations
//! that the `Composer` needs to do with them.
pub(crate) mod domain;
pub(crate) mod evaluations;
pub(crate) mod polynomial;

pub use domain::EvaluationDomain;
pub use evaluations::Evaluations;
pub use polynomial::Polynomial;
