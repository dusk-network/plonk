//! The constraint System module stores the implementation
//! of the PLONK Standard Composer, as well as the circuit
//! tools and abstractions, used by the Composer to generate,
//! build, preprocess & prove constructed circuits.
pub(crate) mod composer;
pub(crate) mod cs_errors;
pub(crate) mod variable;

pub use composer::StandardComposer;
pub use variable::{Variable, WireData};
