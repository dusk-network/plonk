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

/// The result of a scalar multiplication
#[derive(Debug, Clone, Copy)]
pub struct PointScalar {
    point: Point,
    scalar: Variable,
}

impl PointScalar {
    /// Return the generated point
    pub fn point(&self) -> &Point {
        &self.point
    }

    /// Return the internal scalar
    pub fn scalar(&self) -> &Variable {
        &self.scalar
    }
}

impl From<PointScalar> for Point {
    fn from(ps: PointScalar) -> Point {
        ps.point
    }
}

impl StandardComposer {
    /// Converts an JubJubAffine into a constraint system Point
    /// without constraining the values
    pub fn new_private_affine(
        &mut self,
        affine: dusk_jubjub::JubJubAffine,
    ) -> Point {
        let x = self.add_input(affine.get_x());
        let y = self.add_input(affine.get_y());
        Point { x, y }
    }
    /// Converts an JubJubAffine into a constraint system Point
    /// without constraining the values
    pub fn new_public_affine(
        &mut self,
        affine: dusk_jubjub::JubJubAffine,
    ) -> Point {
        let point = self.new_private_affine(affine);
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

    /// Asserts that a point in the circuit is equal to a known public point
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

    /// Conditionally selects a Point based on an input bit
    /// If:
    /// bit == 1 => self,
    /// bit == 0 => point_b,
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
                let bit_0 = composer.add_input(BlsScalar::zero());

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
