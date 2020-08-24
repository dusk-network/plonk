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
/// Elliptic Curve Crypto gates
pub mod ecc;
#[cfg(test)]
pub(crate) mod helper;
/// XOR and AND gates
pub mod logic;
/// Range gate
pub mod range;

pub use composer::TurboComposer;
pub use variable::{Variable, WireData};
