// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Proving system

pub(crate) mod linearization_poly;
pub(crate) mod proof;
pub(crate) mod widget;

cfg_if::cfg_if!(
    if #[cfg(feature = "alloc")] {
        pub(crate) mod quotient_poly;
        pub(crate) mod preprocess;

        pub(crate) use widget::alloc::ProverKey;
        pub(crate) use widget::VerifierKey;

        cfg_if::cfg_if!(
            if #[cfg(feature = "rkyv-impl")] {
                pub use widget::alloc::{ArchivedProverKey, ProverKeyResolver};
            }
        );
    }
);

pub use proof::Proof;

cfg_if::cfg_if!(
    if #[cfg(feature = "rkyv-impl")] {
        pub use proof::{ArchivedProof, ProofResolver};
        pub use widget::{ArchivedVerifierKey, VerifierKeyResolver};
    }
);
