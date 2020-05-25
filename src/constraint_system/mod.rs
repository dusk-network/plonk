//! The constraint System module stores the implementation
//! of the PLONK Standard Composer, as well as the circuit
//! tools and abstractions, used by the Composer to generate,
//! build, preprocess circuits.
pub(crate) mod composer;
pub(crate) mod cs_errors;
pub(crate) mod variable;

/// Simple Arithmetic gates
pub mod arithmetic;
/// Boolean gate
pub mod boolean;
#[cfg(test)]
pub(crate) mod helper;
/// XOR and AND gates
pub mod logic;
/// Range gate
pub mod range;

pub use composer::StandardComposer;
pub use variable::{Variable, WireData};

use crate::fft::Polynomial;
/// Struct that contains all of the selector polynomials in PLONK
/// These polynomials are in coefficient form
pub(crate) struct SelectorPolynomials {
    q_m: Polynomial,
    q_l: Polynomial,
    q_r: Polynomial,
    q_o: Polynomial,
    q_c: Polynomial,
    q_4: Polynomial,
    q_arith: Polynomial,
    q_range: Polynomial,
    q_logic: Polynomial,
    left_sigma: Polynomial,
    right_sigma: Polynomial,
    out_sigma: Polynomial,
    fourth_sigma: Polynomial,
}
