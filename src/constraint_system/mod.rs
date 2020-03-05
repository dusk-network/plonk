//! The constraint system contains the standard composer,
//! as the circuit builder, which allows a program input
//! and delivers the correct wire values for a concatantion
//! of the stages of the snark output for the proof.
//!
//! The constraint system is dependant upon the arithmetic circuit
//! used for PLONK. The arithmetic circuit consists of gates, which are connected
//! in accordance with the required arithmetic action of the programme.
//! The outputs of the circuit is the numeric result of the input.
pub mod linear_combination;
pub mod standard;
pub use linear_combination::{Variable, WireData};
