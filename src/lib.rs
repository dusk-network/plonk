// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://dusk.network/favicon.svg")]
#![doc(html_favicon_url = "https://dusk.network/favicon.png")]
//!<a href="https://codecov.io/gh/dusk-network/plonk">
//!  <img src="https://codecov.io/gh/dusk-network/plonk/branch/master/graph/badge.svg" />
//!</a>
//! <a href="https://github.com/dusk-network/plonk/actions/workflows/dusk_ci.yml/badge.svg">
//! <img src="https://img.shields.io/github/actions/workflow/status/dusk-network/plonk/dusk_ci.yml" />
//! </a>
//! <a href="https://github.com/dusk-network/plonk">
//! <img alt="GitHub issues" src="https://img.shields.io/github/issues-raw/dusk-network/plonk">
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
//! This crate contains a pure-rust implementation done by the
//! [Dusk team](dusk.network) of this algorithm using as a reference
//! implementation this one done by the creators of the protocol:
//!
//! <https://github.com/AztecProtocol/barretenberg/tree/master/cpp/src/barretenberg/plonk/>

// Bitshift/Bitwise ops are allowed to gain performance.
#![allow(clippy::suspicious_arithmetic_impl)]
// Some structs do not have AddAssign or MulAssign impl.
#![allow(clippy::suspicious_op_assign_impl)]
// Witness have always the same names in respect to wires.
#![allow(clippy::many_single_char_names)]
// Bool expr are usually easier to read with match statements.
#![allow(clippy::match_bool)]
// We have quite some functions that require quite some args by it's nature.
// It can be refactored but for now, we avoid these warns.
#![allow(clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

cfg_if::cfg_if!(
if #[cfg(feature = "alloc")] {
    /// `macro_use` will declare `vec!`. However, if `libstd` is present, then this
    /// is declared in the prelude and there will be a conflicting implementation.
    ///
    /// We might have `no_std + alloc` or `std + alloc`, but `macro_use` should be
    /// used only for `no_std`
    #[cfg_attr(not(feature = "std"), macro_use)]
    extern crate alloc;

    mod bit_iterator;
    mod compiler;
    mod composer;
    mod runtime;
    mod util;
    mod transcript;

});

#[cfg(feature = "debug")]
pub(crate) mod debugger;

mod commitment_scheme;
mod error;
mod fft;
mod proof_system;

pub mod prelude;
