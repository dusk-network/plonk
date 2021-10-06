// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

/// Curve addition gate
pub mod curve_addition;
/// Gates related to scalar multiplication
pub mod scalar_mul;

use crate::constraint_system::{TurboComposer, Witness};
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubAffine;

/// Represents a JubJub point in the circuit
#[derive(Debug, Clone, Copy)]
pub struct WitnessPoint {
    x: Witness,
    y: Witness,
}

impl WitnessPoint {
    /// Return the X coordinate of the point
    pub const fn x(&self) -> &Witness {
        &self.x
    }

    /// Return the Y coordinate of the point
    pub const fn y(&self) -> &Witness {
        &self.y
    }
}

impl TurboComposer {
    /// Appends a point in affine form as [`WitnessPoint`]
    pub fn append_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();

        let x = self.append_witness(affine.get_x());
        let y = self.append_witness(affine.get_y());

        WitnessPoint { x, y }
    }

    /// Appends a point in affine form as [`WitnessPoint`]
    ///
    /// Creates two public inputs as `(x, y)`
    pub fn append_public_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();
        let point = self.append_point(affine);

        self.assert_equal_constant(
            point.x,
            BlsScalar::zero(),
            Some(-affine.get_x()),
        );

        self.assert_equal_constant(
            point.y,
            BlsScalar::zero(),
            Some(-affine.get_y()),
        );

        point
    }

    /// Constrain a point into the circuit description and return an allocated
    /// [`WitnessPoint`] with its coordinates
    pub fn append_constant_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();

        let x = self.append_constant(affine.get_x());
        let y = self.append_constant(affine.get_y());

        WitnessPoint { x, y }
    }

    /// Create an identity [`WitnessPoint`] constrained by the circuit
    /// description
    pub fn append_constant_identity(&mut self) -> WitnessPoint {
        let x = self.constant_zero();
        let y = self.append_constant(BlsScalar::one());

        WitnessPoint { x, y }
    }

    /// Asserts `point == public`.
    ///
    /// Will add `public` affine coordinates `(x,y)` as public inputs
    pub fn assert_equal_public_point<P: Into<JubJubAffine>>(
        &mut self,
        point: WitnessPoint,
        public: P,
    ) {
        let public = public.into();

        self.assert_equal_constant(
            point.x,
            BlsScalar::zero(),
            Some(-public.get_x()),
        );

        self.assert_equal_constant(
            point.y,
            BlsScalar::zero(),
            Some(-public.get_y()),
        );
    }

    /// Asserts `a == b` by appending two gates
    pub fn assert_equal_point(&mut self, a: WitnessPoint, b: WitnessPoint) {
        self.assert_equal(a.x, b.x);
        self.assert_equal(b.y, b.y);
    }

    /// Conditionally selects a [`WitnessPoint`] based on an input bit.
    ///
    /// bit == 1 => a,
    /// bit == 0 => b,
    ///
    /// `bit` is expected to be constrained by [`TurboComposer::gate_boolean`]
    pub fn component_select_point(
        &mut self,
        a: WitnessPoint,
        b: WitnessPoint,
        bit: Witness,
    ) -> WitnessPoint {
        let x = self.component_select(bit, *a.x(), *b.x());
        let y = self.component_select(bit, *a.y(), *b.y());

        WitnessPoint { x, y }
    }

    /// Conditionally selects identity as [`WitnessPoint`] based on an input
    /// bit.
    ///
    /// bit == 1 => a,
    /// bit == 0 => identity,
    ///
    /// `bit` is expected to be constrained by [`TurboComposer::gate_boolean`]
    pub fn component_select_identity(
        &mut self,
        bit: Witness,
        a: WitnessPoint,
    ) -> WitnessPoint {
        let x = self.gate_select_zero(bit, *a.x());
        let y = self.gate_select_one(bit, *a.y());

        WitnessPoint { x, y }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::helper::*;

    #[test]
    fn test_component_select_point() {
        let res = gadget_tester(
            |composer| {
                let bit_1 = composer.append_witness(BlsScalar::one());
                let bit_0 = composer.constant_zero();

                let point_a = composer.append_constant_identity();
                let point_b = WitnessPoint {
                    x: composer.append_witness(BlsScalar::from(10u64)),
                    y: composer.append_witness(BlsScalar::from(20u64)),
                };

                let choice =
                    composer.component_select_point(point_a, point_b, bit_1);

                composer.assert_equal_point(point_a, choice);

                let choice =
                    composer.component_select_point(point_a, point_b, bit_0);
                composer.assert_equal_point(point_b, choice);
            },
            32,
        );
        assert!(res.is_ok());
    }
}
