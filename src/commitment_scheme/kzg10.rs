// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Implementation of the KZG10 polynomial commitment scheme.

cfg_if::cfg_if!(
if #[cfg(feature = "alloc")]
{
    pub mod key;
    pub mod srs;

    pub(crate) use proof::alloc::AggregateProof;

    pub use key::{CommitKey, OpeningKey};
    pub use srs::PublicParameters;

    cfg_if::cfg_if!(
        if #[cfg(feature = "rkyv-impl")] {
            pub use key::{ArchivedCommitKey, CommitKeyResolver, ArchivedOpeningKey, OpeningKeyResolver};
            pub use srs::{ArchivedPublicParameters, PublicParametersResolver};
        }
    );
});

pub(crate) mod commitment;
pub(crate) mod proof;

pub(crate) use commitment::Commitment;
