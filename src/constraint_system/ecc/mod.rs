// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

/// Curve addition gate
pub mod curve_addition;
/// Gates related to scalar multiplication
pub mod scalar_mul;

use crate::constraint_system::{variable::Variable, StandardComposer};
use dusk_bls12_381::BlsScalar;

/// Represents a JubJub point in the circuit
#[derive(Debug, Clone, Copy)]
pub struct Point {
    x: Variable,
    y: Variable,
}

impl Point {
    /// Returns an identity point
    pub fn identity(composer: &mut StandardComposer) -> Point {
        let one = composer.add_witness_to_circuit_description(BlsScalar::one());
        Point {
            x: composer.zero_var,
            y: one,
        }
    }
    /// Return the X coordinate of the point
    pub fn x(&self) -> &Variable {
        &self.x
    }

    /// Return the Y coordinate of the point
    pub fn y(&self) -> &Variable {
        &self.y
    }
}

impl StandardComposer {
    /// Converts an JubJubAffine into a constraint system Point
    /// without constraining the values
    pub fn add_affine(&mut self, affine: dusk_jubjub::JubJubAffine) -> Point {
        let x = self.add_input(affine.get_x());
        let y = self.add_input(affine.get_y());
        Point { x, y }
    }

    /// Converts an JubJubAffine into a constraint system Point
    /// without constraining the values
    pub fn add_public_affine(
        &mut self,
        affine: dusk_jubjub::JubJubAffine,
    ) -> Point {
        let point = self.add_affine(affine);
        self.constrain_to_constant(
            point.x,
            BlsScalar::zero(),
            Some(-affine.get_x()),
        );
        self.constrain_to_constant(
            point.y,
            BlsScalar::zero(),
            Some(-affine.get_y()),
        );

        point
    }

    /// Add the provided affine point as a circuit description and return its
    /// constrained witness value
    pub fn add_affine_to_circuit_description(
        &mut self,
        affine: dusk_jubjub::JubJubAffine,
    ) -> Point {
        // Not using individual gates because one of these may be zero
        let x = self.add_witness_to_circuit_description(affine.get_x());
        let y = self.add_witness_to_circuit_description(affine.get_y());

        Point { x, y }
    }

    /// Asserts that a [`Point`] in the circuit is equal to a known public
    /// point.
    pub fn assert_equal_public_point(
        &mut self,
        point: Point,
        public_point: dusk_jubjub::JubJubAffine,
    ) {
        self.constrain_to_constant(
            point.x,
            BlsScalar::zero(),
            Some(-public_point.get_x()),
        );
        self.constrain_to_constant(
            point.y,
            BlsScalar::zero(),
            Some(-public_point.get_y()),
        );
    }
    /// Asserts that a point in the circuit is equal to another point in the
    /// circuit
    pub fn assert_equal_point(&mut self, point_a: Point, point_b: Point) {
        self.assert_equal(point_a.x, point_b.x);
        self.assert_equal(point_b.y, point_b.y);
    }

    /// Adds to the circuit description the conditional selection of the
    /// a point between two of them.
    /// bit == 1 => point_a,
    /// bit == 0 => point_b,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Variable`] should had previously
    /// been constrained to be either 1 or 0 using a bool constrain. See:
    /// [`StandardComposer::boolean_gate`].
    pub fn conditional_point_select(
        &mut self,
        point_a: Point,
        point_b: Point,
        bit: Variable,
    ) -> Point {
        let x = self.conditional_select(bit, *point_a.x(), *point_b.x());
        let y = self.conditional_select(bit, *point_a.y(), *point_b.y());

        Point { x, y }
    }

    /// Adds to the circuit description the conditional selection of the
    /// identity point:
    /// bit == 1 => value,
    /// bit == 0 => 1,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Variable`] should had previously
    /// been constrained to be either 1 or 0 using a bool constrain. See:
    /// [`StandardComposer::boolean_gate`].
    fn conditional_select_identity(
        &mut self,
        bit: Variable,
        point_b: Point,
    ) -> Point {
        let x = self.conditional_select_zero(bit, *point_b.x());
        let y = self.conditional_select_one(bit, *point_b.y());

        Point { x, y }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::helper::*;

    #[test]
    fn test_conditional_select_point() {
        let res = gadget_tester(
            |composer| {
                let bit_1 = composer.add_input(BlsScalar::one());
                let bit_0 = composer.zero_var();

                let point_a = Point::identity(composer);
                let point_b = Point {
                    x: composer.add_input(BlsScalar::from(10u64)),
                    y: composer.add_input(BlsScalar::from(20u64)),
                };

                let choice =
                    composer.conditional_point_select(point_a, point_b, bit_1);

                composer.assert_equal_point(point_a, choice);

                let choice =
                    composer.conditional_point_select(point_a, point_b, bit_0);
                composer.assert_equal_point(point_b, choice);
            },
            32,
        );
        assert!(res.is_ok());
    }
}
