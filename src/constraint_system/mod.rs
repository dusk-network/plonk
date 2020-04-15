//! The constraint System module stores the implementation
//! of the PLONK Standard Composer, as well as the circuit
//! tools and abstractions, used by the Composer to generate,
//! build, preprocess & prove constructed circuits.
pub mod standard;
pub mod variable;
mod widget;
pub use variable::{Variable, WireData};
