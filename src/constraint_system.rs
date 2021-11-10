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
pub(crate) mod constraint;
pub(crate) mod ecc;
pub(crate) mod logic;
pub(crate) mod range;
pub(crate) mod witness;

pub(crate) use constraint::{Selector, WiredWitness};
pub(crate) use witness::WireData;

mod arithmetic;
mod boolean;

#[cfg(feature = "std")]
#[cfg(test)]
pub(crate) mod helper;

pub use composer::TurboComposer;
pub use constraint::Constraint;
pub use ecc::WitnessPoint;
pub use witness::Witness;
