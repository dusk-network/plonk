// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! FFT module contains the tools needed by the Composer backend
//! to know and use the logic behind Polynomials. As well as
//! the operations that the `Composer` needs to peform with them.
pub(crate) mod domain;
#[cfg(feature = "alloc")]
pub(crate) mod evaluations;
#[cfg(feature = "alloc")]
pub(crate) mod polynomial;

#[allow(unused_imports)]
pub(crate) use domain::EvaluationDomain;
#[cfg(feature = "alloc")]
pub(crate) use evaluations::Evaluations;
#[cfg(feature = "alloc")]
pub(crate) use polynomial::Polynomial;
