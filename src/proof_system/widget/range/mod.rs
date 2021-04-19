// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
mod proverkey;

mod verifierkey;

#[cfg(feature = "alloc")]
pub(crate) use proverkey::ProverKey;

pub(crate) use verifierkey::VerifierKey;
