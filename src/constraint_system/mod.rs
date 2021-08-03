// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The constraint System module stores the implementation
//! of the PLONK Standard Composer, as well as the circuit
//! tools and abstractions, used by the Composer to generate,
//! build, preprocess circuits.
pub(crate) mod composer;
pub(crate) mod divide_w_recip;
pub(crate) mod variable;

/// Simple Arithmetic gates
mod arithmetic;
/// Boolean gate
mod boolean;
/// Elliptic Curve Crypto gates
pub mod ecc;

#[cfg(feature = "std")]
#[cfg(test)]
pub(crate) mod helper;
/// XOR and AND gates
pub mod logic;
/// Range gate
pub mod range;
/// Zelbet Functionality
pub mod zelbet;

pub use composer::StandardComposer;
pub use ecc::Point;
pub use variable::Variable;
pub(crate) use variable::WireData;
