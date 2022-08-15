// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::Witness;
use dusk_bls12_381::BlsScalar;

/// Represents a JubJub point in the circuit
#[derive(Debug, Clone, Copy)]
pub struct WitnessPoint {
    x: Witness,
    y: Witness,
}

impl WitnessPoint {
    #[allow(dead_code)]
    pub(crate) const fn new(x: Witness, y: Witness) -> Self {
        Self { x, y }
    }

    /// Return the X coordinate of the point
    pub const fn x(&self) -> &Witness {
        &self.x
    }

    /// Return the Y coordinate of the point
    pub const fn y(&self) -> &Witness {
        &self.y
    }
}

#[derive(Debug, Clone, Copy)]
/// Contains all of the components needed to verify that a bit scalar
/// multiplication was computed correctly
pub(crate) struct WnafRound<T: Into<Witness>> {
    /// This is the accumulated x coordinate point that we wish to add (so
    /// far.. depends on where you are in the scalar mul) it is linked to
    /// the wnaf entry, so must not be revealed
    pub acc_x: T,
    /// This is the accumulated y coordinate
    pub acc_y: T,

    /// This is the wnaf accumulated entry
    /// For all intents and purposes, you can think of this as the secret bit
    pub accumulated_bit: T,

    /// This is the multiplication of x_\alpha * y_\alpha
    /// we need this as a distinct wire, so that the degree of the polynomial
    /// does not go over 4
    pub xy_alpha: T,
    /// This is the possible x co-ordinate of the wnaf point we are going to
    /// add Actual x-co-ordinate = b_i * x_\beta
    pub x_beta: BlsScalar,
    /// This is the possible y co-ordinate of the wnaf point we are going to
    /// add Actual y coordinate = (b_i)^2 [y_\beta -1] + 1
    pub y_beta: BlsScalar,
    /// This is the multiplication of x_\beta * y_\beta
    pub xy_beta: BlsScalar,
}
