//! The constrain system contains the standard composer,
//! as the circuit builder, which allows a program input
//! and delivers the correct wire values for a concatantion
//! of the stages of the snark output for the proof.
pub mod linear_combination;
pub mod standard;
pub use linear_combination::{Variable, WireData};
