// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

//! FFT module contains the tools needed by the Composer backend
//! to know and use the logic behind Polynomials. As well as
//! the operations that the `Composer` needs to peform with them.
pub(crate) mod domain;
pub(crate) mod evaluations;
pub(crate) mod fft_errors;
pub(crate) mod polynomial;

pub use domain::EvaluationDomain;
pub use evaluations::Evaluations;
pub use polynomial::Polynomial;
