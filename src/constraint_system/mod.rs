//! The constraint System module stores the implementation
//! of the PLONK Standard Composer, as well as the circuit
//! tools and abstractions, used by the Composer to generate,
//! build, preprocess circuits.
pub(crate) mod composer;
pub(crate) mod cs_errors;
pub(crate) mod variable;

// XXX : Put all of these in a composer folder
pub(crate) mod arithmetic;
pub(crate) mod boolean;
#[cfg(test)]
pub(crate) mod helper;
pub(crate) mod logic;
pub(crate) mod range;

pub use composer::StandardComposer;
pub use variable::{Variable, WireData};
