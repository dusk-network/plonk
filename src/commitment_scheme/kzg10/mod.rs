// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Implementation of the KZG10 polynomial commitment scheme.
pub mod commitment;

cfg_if::cfg_if!(
    if #[cfg(feature = "alloc")]
    {
        pub mod key;
        pub mod proof;
        pub mod srs;
        pub use key::{CommitKey, OpeningKey};
        pub(crate) use proof::{AggregateProof, Proof};
        pub use srs::PublicParameters;
    }
);

pub(crate) use commitment::Commitment;
