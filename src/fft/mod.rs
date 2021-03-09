// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! FFT module contains the tools needed by the Composer backend
//! to know and use the logic behind Polynomials. As well as
//! the operations that the `Composer` needs to peform with them.
pub(crate) mod domain;
pub(crate) mod evaluations;
pub(crate) mod polynomial;

pub(crate) use domain::EvaluationDomain;
pub(crate) use evaluations::Evaluations;
pub(crate) use polynomial::Polynomial;
