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
pub(crate) mod variable;

/// Simple Arithmetic gates
pub mod arithmetic;
/// Boolean gate
pub mod boolean;
/// Elliptic Curve Crypto gates
pub mod ecc;
#[cfg(test)]
pub(crate) mod helper;
/// XOR and AND gates
pub mod logic;
/// Range gate
pub mod range;

pub(crate) use variable::WireData;
pub use composer::StandardComposer;
pub use variable::Variable;
