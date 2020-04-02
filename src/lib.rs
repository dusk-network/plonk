// Bitshift/Bitwise ops are allowed to gain performance.
#![allow(clippy::suspicious_arithmetic_impl)]
// Some structs do not have AddAssign or MulAssign impl.
#![allow(clippy::suspicious_op_assign_impl)]
// Variables have always the same names in respect to wires.
#![allow(clippy::many_single_char_names)]
// Bool expr are usually easier to read with match statements.
#![allow(clippy::match_bool)]
mod bit_iterator;
pub mod commitment_scheme;
pub mod constraint_system;
pub mod fft;
mod permutation;
pub mod transcript;
mod util;

#[macro_use]
extern crate failure;
