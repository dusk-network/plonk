//! The constraint System module stores the implementation
//! of the PLONK Standard Composer, as well as the circuit
//! tools and abstractions, used by the Composer to generate,
//! build, preprocess & prove constructed circuits.
pub mod variable;
pub use variable::{Variable, WireData};
pub mod composer;
mod cs_errors;

pub use composer::StandardComposer;
