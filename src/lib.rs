#![cfg_attr(feature = "nightly", feature(external_doc))]
//! Permutations over Lagrange-bases for Oecumenical Noninteractive
//! arguments of Knowledge (PLONK) is a zero knowledge proof system.
//!
//! This protocol was created by:
//! - Ariel Gabizon (Protocol Labs),
//! - Zachary J. Williamson (Aztec Protocol)
//! - Oana Ciobotaru
//!
//! This crate contains a pure-rust implementation done by the [DuskNetwork team](dusk.network)
//! of this algorithm using as a reference implementation this one done
//! by the creators of the protocol:
//!
//! https://github.com/AztecProtocol/barretenberg/blob/master/barretenberg/src/aztec/plonk/
//!
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
pub mod proving_system;
pub mod transcript;
mod util;

#[macro_use]
extern crate failure;

#[cfg(all(test, feature = "serde"))]
extern crate bincode;
#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "nightly")]
#[doc(include = "../docs/notes-intro.md")]
pub mod notes {
    #[cfg(feature = "nightly")]
    #[doc(include = "../docs/notes-commitments.md")]
    pub mod commitment_schemes {}
    #[cfg(feature = "nightly")]
    #[doc(include = "../docs/notes-pa.md")]
    pub mod permutation_arguments {}
    #[cfg(feature = "nightly")]
    #[doc(include = "../docs/notes-snark.md")]
    pub mod snark_construction {}
    #[cfg(feature = "nightly")]
    #[doc(include = "../docs/notes-prove-verify.md")]
    pub mod prove_verify {}
    #[cfg(feature = "nightly")]
    #[doc(include = "../docs/notes-pa.md")]
    pub mod unbalanced_perm_args {}
    #[cfg(feature = "nightly")]
    #[doc(include = "../docs/notes-KZG10.md")]
    pub mod kzg10_docs {}
}
