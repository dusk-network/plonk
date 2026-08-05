// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regressions for the composer's gadgets, one module per gadget
//! family, over the scaffolding in [`support`].
//!
//! Each of them compiles a verifier key from an honest gadget and then proves
//! against it with a fork of that gadget filled with forged witnesses, so they
//! need the crate-private constraint emitters the honest gadgets are built
//! from.

mod evaluated_output;
mod fixed_base;
mod logic;
mod point;
mod range;
mod support;
mod truncate;
