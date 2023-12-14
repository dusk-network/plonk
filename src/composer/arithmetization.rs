// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

use crate::constraint_system::Witness;

/// Represents a polynomial in coefficient form with its associated wire data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arithmetization {
    // Selectors
    /// Multiplier selector
    pub(crate) q_m: BlsScalar,
    /// Left wire selector
    pub(crate) q_l: BlsScalar,
    /// Right wire selector
    pub(crate) q_r: BlsScalar,
    /// Output wire selector
    pub(crate) q_o: BlsScalar,
    /// Fourth wire selector
    pub(crate) q_4: BlsScalar,
    /// Constant wire selector
    pub(crate) q_c: BlsScalar,
    /// Arithmetic wire selector
    pub(crate) q_arith: BlsScalar,
    /// Range selector
    pub(crate) q_range: BlsScalar,
    /// Logic selector
    pub(crate) q_logic: BlsScalar,
    /// Fixed base group addition selector
    pub(crate) q_fixed_group_add: BlsScalar,
    /// Variable base group addition selector
    pub(crate) q_variable_group_add: BlsScalar,

    /// Left wire witness.
    pub(crate) w_a: Witness,
    /// Right wire witness.
    pub(crate) w_b: Witness,
    /// Output wire witness.
    pub(crate) w_o: Witness,
    /// Fourth wire witness.
    pub(crate) w_d: Witness,
}
