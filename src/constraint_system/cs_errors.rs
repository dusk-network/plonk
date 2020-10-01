// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Errors related to the Constraint system

use thiserror::Error;

/// Represents an error on the Circuit preprocessing stage.
#[derive(Error, Debug)]
pub enum PreProcessingError {
    /// This error occurs when an error triggers during the preprocessing
    /// stage.
    #[error("the length of the wires it's not the same")]
    MismatchedPolyLen,
}
