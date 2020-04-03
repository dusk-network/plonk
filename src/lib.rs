//! Aztec's PLONK system implementation built by the [Dusk Network team](dusk.network)
//!
//! This code has not been audited or reviewed so no security assumptions
//! can be made over it.
//!
//! USE AT YOUR OWN RISK.
// Bitshift/Bitwise ops are allowed to gain performance.
#![allow(clippy::suspicious_arithmetic_impl)]
// Some structs do not have AddAssign or MulAssign impl.
#![allow(clippy::suspicious_op_assign_impl)]
// Variables have always the same names in respect to wires.
#![allow(clippy::many_single_char_names)]
// Bool expr are usually easier to read with match statements.
#![allow(clippy::match_bool)]
#![deny(intra_doc_link_resolution_failure)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

mod bit_iterator;
pub mod commitment_scheme;
pub mod constraint_system;
pub mod fft;
mod permutation;
pub mod transcript;
mod util;

#[macro_use]
extern crate failure;
