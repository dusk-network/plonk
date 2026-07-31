// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

use crate::prelude::Witness;

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

/// A [`WitnessPoint`] whose membership in the prime-order subgroup of the
/// embedded curve has been established.
///
/// # Boundary rule
///
/// Every point entering a circuit must have its subgroup membership
/// established before it takes part in group arithmetic:
///
/// - **private or prover-controlled** points must be constrained in-circuit
///   with [`Composer::assert_torsion_free_point`];
/// - **constant** points are validated natively at circuit build by
///   [`Composer::append_constant_point`], which returns the typed point itself;
/// - **public** points may be validated outside the circuit as part of the
///   accepting verifier's protocol and wrapped with [`Self::new_unchecked`], or
///   constrained in-circuit with [`Composer::assert_torsion_free_point`] like
///   any other witness point — the costlier route, but it keeps the obligation
///   inside the proof when the consumer cannot audit every verifier
///   implementation.
///
/// Once established, membership is preserved by the group operations
/// ([`Composer::component_add_point`], [`Composer::component_sub_point`],
/// [`Composer::component_mul_point`], [`Composer::component_neg_point`],
/// [`Composer::component_select_identity`]), which therefore take and return
/// this type: a point in the subgroup cannot leave it.
///
/// Decoding bytes into an affine point or binding a point to a commitment
/// does **not** establish subgroup membership on its own: decoding only
/// guarantees an on-curve point, and a commitment only binds the value.
/// [`Composer::component_mul_generator`] does return the typed point: it
/// validates its generator to be of exact prime order, so every multiple of
/// it lies in the subgroup.
///
/// The prime-order subgroup contains the identity, so a torsion-free point
/// may still be the identity — consumers that must rule it out have to
/// constrain that separately.
///
/// [`Composer::assert_torsion_free_point`]: crate::prelude::Composer::assert_torsion_free_point
/// [`Composer::append_constant_point`]: crate::prelude::Composer::append_constant_point
/// [`Composer::component_add_point`]: crate::prelude::Composer::component_add_point
/// [`Composer::component_sub_point`]: crate::prelude::Composer::component_sub_point
/// [`Composer::component_mul_point`]: crate::prelude::Composer::component_mul_point
/// [`Composer::component_neg_point`]: crate::prelude::Composer::component_neg_point
/// [`Composer::component_select_identity`]: crate::prelude::Composer::component_select_identity
/// [`Composer::component_mul_generator`]: crate::prelude::Composer::component_mul_generator
#[derive(Debug, Clone, Copy)]
pub struct TorsionFreeWitnessPoint(WitnessPoint);

impl TorsionFreeWitnessPoint {
    /// Wrap a [`WitnessPoint`] whose subgroup membership has been established
    /// outside the circuit.
    ///
    /// # Caller obligation
    ///
    /// This constructor is an explicit escape hatch and adds no constraints:
    /// the caller vouches that the wrapped point is a prime-order subgroup
    /// element. That is only sound for points the prover cannot choose
    /// freely — public inputs whose membership is checked off-circuit, or
    /// constants known to lie in the subgroup. For public inputs the
    /// off-circuit check must be enforced by the **accepting verifier's
    /// protocol**, not merely performed by an honest prover: the proof
    /// system itself only receives flat scalars and cannot know the check
    /// happened, so a verifier that accepts unchecked inputs re-opens the
    /// soundness hole in the consumer circuit. Wrapping a prover-controlled
    /// point without an in-circuit check breaks soundness the same way: use
    /// [`Composer::assert_torsion_free_point`] for those instead.
    ///
    /// [`Composer::assert_torsion_free_point`]: crate::prelude::Composer::assert_torsion_free_point
    pub const fn new_unchecked(point: WitnessPoint) -> Self {
        Self(point)
    }

    /// Return the X coordinate of the point
    pub const fn x(&self) -> &Witness {
        self.0.x()
    }

    /// Return the Y coordinate of the point
    pub const fn y(&self) -> &Witness {
        self.0.y()
    }
}

impl From<TorsionFreeWitnessPoint> for WitnessPoint {
    fn from(point: TorsionFreeWitnessPoint) -> Self {
        point.0
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
