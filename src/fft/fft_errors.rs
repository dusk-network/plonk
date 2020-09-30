// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Errors related to the fft module.

use thiserror::Error;

/// Defines all of the possible FFTError types that we could have when
/// we are working with the `fft` module.
#[derive(Error, Debug)]
pub enum FFTErrors {
    /// This error occurs when an error triggers on any of the fft module
    /// functions.
    #[error(
        "Log-size of the EvaluationDomain group > TWO_ADACITY\
    Size: {:?} > TWO_ADACITY = {:?}",
        log_size_of_group,
        adacity
    )]
    InvalidEvalDomainSize {
        /// Log size of the group
        log_size_of_group: u32,
        /// Two adacity generated
        adacity: u32,
    },
}
