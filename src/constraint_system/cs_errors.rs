// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Errors related to the Constraint system

use crate::commitment_scheme::kzg10::errors::KZG10Errors;
use crate::fft::fft_errors::FFTErrors;

/// Represents an error on the Circuit preprocessing stage.
#[derive(core::fmt::Debug)]
pub enum PreProcessingErrors {
    /// This error occurs when an error triggers during the preprocessing
    /// stage.
    MismatchedPolyLen,
    /// This error occurs when no evaluation domain can be constructed.
    CouldNotConstructEvaluationDomain(FFTErrors),
    /// This error occurs when a poly can not be committed to.
    CouldNotCommitToPoly(KZG10Errors),
    /// This error occurs when the Prover structure already contains a
    /// preprocessed circuit inside, but you call preprocess again.
    CircuitAlreadyPreprocessed,
}
