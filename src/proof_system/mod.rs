// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Proving system

cfg_if::cfg_if!(
    if #[cfg(feature = "alloc")] {
        mod preprocess;
        /// Represents a PLONK Prover
        pub mod prover;
        pub use proof::alloc::*;
        pub(crate) mod quotient_poly;
        /// Represents a PLONK Verifier
        pub mod verifier;
        pub use prover::Prover;
        pub use verifier::Verifier;
        pub use widget::alloc::*;
        pub(crate) mod widget;
        pub use widget::VerifierKey;
    }
);

/// Represents PLONK Proof
pub mod proof;
pub use proof::Proof;
pub(crate) mod linearisation_poly;
