// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Ideally we should cleanly abstract away the polynomial commitment scheme
//! We note that PLONK makes use of the linearization technique
//! conceived in SONIC [Mary Maller].
//!
//! This technique implicitly requires the
//! commitment scheme to be homomorphic. `Merkle Tree like` techniques such as
//! FRI are not homomorphic and therefore for PLONK to be usable with all
//! commitment schemes without modification, one would need to remove the
//! linearizer

mod kzg10;

pub(crate) use kzg10::Commitment;

#[cfg(feature = "alloc")]
pub(crate) use kzg10::AggregateProof;

#[cfg(feature = "alloc")]
pub(crate) use kzg10::{CommitKey, OpeningKey};

#[cfg(feature = "alloc")]
pub use kzg10::PublicParameters;

#[cfg(all(feature = "alloc", feature = "rkyv-impl"))]
pub use kzg10::{
    ArchivedCommitKey, ArchivedOpeningKey, ArchivedPublicParameters,
    CommitKeyResolver, OpeningKeyResolver, PublicParametersResolver,
};
