// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! proving system

pub(crate) mod linearisation_poly;
mod preprocess;

/// Represents a PLONK Proof
pub(crate) mod proof;
/// Represents a PLONK Prover
pub(crate) mod prover;
pub(crate) mod quotient_poly;
/// Represents a PLONK Verifier
pub(crate) mod verifier;
pub(crate) mod widget;

pub use proof::Proof;
pub use prover::Prover;
pub use verifier::Verifier;
pub use widget::{ProverKey, VerifierKey};
