// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://lh3.googleusercontent.com/SmwswGxtgIANTbDrCOn5EKcRBnVdHjmYsHYxLq2HZNXWCQ9-fZyaea-bNgdX9eR0XGSqiMFi=w128-h128-e365"
)]
#![doc(html_favicon_url = "https://dusk.network/lib/img/favicon-16x16.png")]
//!<a href="https://codecov.io/gh/dusk-network/plonk">
//!  <img src="https://codecov.io/gh/dusk-network/plonk/branch/master/graph/badge.svg" />
//!</a>
//! <a href="https://travis-ci.com/dusk-network/plonk">
//! <img src="https://travis-ci.com/dusk-network/plonk.svg?branch=master" />
//! </a>
//! <a href="https://github.com/dusk-network/plonk">
//! <img alt="GitHub issues" src="https://img.shields.io/github/issues-raw/dusk-network/plonk?style=plastic">
//! </a>
//! <a href="https://github.com/dusk-network/plonk/blob/master/LICENSE">
//! <img alt="GitHub" src="https://img.shields.io/github/license/dusk-network/plonk?color=%230E55EF">
//! </a>
//!
//!
//! Permutations over Lagrange-bases for Oecumenical Noninteractive
//! arguments of Knowledge (PLONK) is a zero knowledge proof system.
//!
//! This protocol was created by:
//! - Ariel Gabizon (Protocol Labs),
//! - Zachary J. Williamson (Aztec Protocol)
//! - Oana Ciobotaru
//!
//! This crate contains a pure-rust implementation done by the [DuskNetwork
//! team](dusk.network) of this algorithm using as a reference implementation
//! this one done by the creators of the protocol:
//!
//! <https://github.com/AztecProtocol/barretenberg/blob/master/barretenberg/src/aztec/plonk/>
//!
//! If you want to see library usage examples, please check:
//! <https://github.com/dusk-network/plonk/tree/v0.1.0/examples>
// Bitshift/Bitwise ops are allowed to gain performance.
#![allow(clippy::suspicious_arithmetic_impl)]
// Some structs do not have AddAssign or MulAssign impl.
#![allow(clippy::suspicious_op_assign_impl)]
// Variables have always the same names in respect to wires.
#![allow(clippy::many_single_char_names)]
// Bool expr are usually easier to read with match statements.
#![allow(clippy::match_bool)]
// We have quite some functions that require quite some args by it's nature.
// It can be refactored but for now, we avoid these warns.
#![allow(clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

cfg_if::cfg_if!(
if #[cfg(feature = "alloc")] {
    #[macro_use]
    extern crate alloc;
    pub mod constraint_system;
    mod bit_iterator;
    pub mod circuit;
    mod util;
    mod permutation;
});

pub mod commitment_scheme;
pub mod error;
mod fft;
pub mod plookup;
pub mod prelude;
pub mod proof_system;
mod transcript;

#[doc = include_str!("../docs/notes-intro.md")]
pub mod notes {
    #[doc = include_str!("../docs/notes-commitments.md")]
    pub mod commitment_schemes {}
    #[doc = include_str!("../docs/notes-snark.md")]
    pub mod snark_construction {}
    #[doc = include_str!("../docs/notes-prove-verify.md")]
    pub mod prove_verify {}
    #[doc = include_str!("../docs/notes-KZG10.md")]
    pub mod kzg10_docs {}
}

/// Re-exported dusk-bls12_381 fork.
pub use dusk_bls12_381 as bls12_381;

/// Re-exported dusk-jubjub fork.
pub use dusk_jubjub as jubjub;
