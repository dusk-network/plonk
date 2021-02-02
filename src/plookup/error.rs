// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Errors related to PLOOKUP

use thiserror::Error;

/// Represents an error encountered when working with PLOOKUP tables.
#[derive(Error, Debug)]
pub enum PlookupErrors {
    /// This error occurs when the user tries to look up a value which
    /// does not exist in the table.
    #[error("the requested element was not indexed in the lookup table")]
    ElementNotIndexed,
}
