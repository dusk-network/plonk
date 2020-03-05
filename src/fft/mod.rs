//! FFT module contains the encoding for the multiplication
//! of polynomials over select finite fields.
//!
/// Fast fourier transformations (FFT) computes both the discrete
/// fourier transforms (DFT) and the inverse DFT of a given polynomial.
/// This is done by using the coefficient form of the polynomial to
/// calculate the product.
pub(crate) mod constants;
pub(crate) mod domain;
pub(crate) mod evaluations;
pub(crate) mod polynomial;

pub use domain::EvaluationDomain;
pub use evaluations::Evaluations;
pub use polynomial::Polynomial;
