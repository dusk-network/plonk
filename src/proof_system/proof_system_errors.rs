// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Errors related to the proof_system module.

use crate::commitment_scheme::kzg10::errors::KZG10Errors;
use crate::constraint_system::cs_errors::PreProcessingErrors;
use crate::fft::fft_errors::FFTErrors;

/// Defines all of the possible ProofError types that we could have when
/// we are working with the `proof_system` module.
#[derive(core::fmt::Debug)]
pub enum ProofErrors {
    /// This error occurs when the verification of a `Proof` fails.
    ProofVerificationError,
    /// This error occurs when the evaluation domain can not be constructed.
    CouldNotConstructEvaluationDomain(FFTErrors),
    /// This error occurs when preprocessing of a circuit fails.
    CouldNotPreProcessCircuit(PreProcessingErrors),
    /// This error occurs when a poly can not be committed to.
    CouldNotCommitToPoly(KZG10Errors),
    /// This error occurs when the computation of the quotient poly fails.
    CouldNotComputeQuotientPoly(FFTErrors),
}
