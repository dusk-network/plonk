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
use dusk_jubjub::EDWARDS_D;

/// Represents a JubJub point in the circuit
#[derive(Debug, Clone, Copy)]
pub struct Point {
    x: Variable,
    y: Variable,
}

impl Point {
    /// Return the X coordinate of the point
    pub fn x(&self) -> &Variable {
        &self.x
    }

    /// Return the Y coordinate of the point
    pub fn y(&self) -> &Variable {
        &self.y
    }

    /// Returns an identity point
    pub fn identity(composer: &mut StandardComposer) -> Point {
        let one = composer.add_witness_to_circuit_description(BlsScalar::one());
        Point {
            x: composer.zero_var,
            y: one,
        }
    }

    /// Converts an JubJubAffine into a constraint system Point
    /// without constraining the values
    pub fn from_private_affine(
        composer: &mut StandardComposer,
        affine: dusk_jubjub::JubJubAffine,
    ) -> Point {
        let x = composer.add_input(affine.get_x());
        let y = composer.add_input(affine.get_y());
        Point { x, y }
    }
    /// Converts an JubJubAffine into a constraint system Point
    /// without constraining the values
    pub fn from_public_affine(
        composer: &mut StandardComposer,
        affine: dusk_jubjub::JubJubAffine,
    ) -> Point {
        let point = Point::from_private_affine(composer, affine);
        composer.constrain_to_constant(
            point.x,
            BlsScalar::zero(),
            Some(-affine.get_x()),
        );
        composer.constrain_to_constant(
            point.y,
            BlsScalar::zero(),
            Some(-affine.get_y()),
        );

        point
    }

    /// Conditionally selects a Point based on an input bit
    /// If:
    ///     bit == 1 => self,
    ///     bit == 0 => point_b,
    pub fn conditional_select(
        &self,
        composer: &mut StandardComposer,
        bit: Variable,
        point_b: Point,
    ) -> Point {
        let x = composer.conditional_select(bit, *self.x(), *point_b.x());
        let y = composer.conditional_select(bit, *self.y(), *point_b.y());

        Point { x, y }
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

impl Point {
    /// Adds two curve points together
    pub fn add(
        &self,
        composer: &mut StandardComposer,
        point_b: Point,
    ) -> Point {
        self.fast_add(composer, point_b)
    }

    /// Adds two curve points together using arithmetic gates
    pub fn slow_add(
        &self,
        composer: &mut StandardComposer,
        point_b: Point,
    ) -> Point {
        let x1 = self.x;
        let y1 = self.y;

        let x2 = point_b.x;
        let y2 = point_b.y;

        // x1 * y2
        let x1_y2 =
            composer.mul(BlsScalar::one(), x1, y2, BlsScalar::zero(), None);
        // y1 * x2
        let y1_x2 =
            composer.mul(BlsScalar::one(), y1, x2, BlsScalar::zero(), None);
        // y1 * y2
        let y1_y2 =
            composer.mul(BlsScalar::one(), y1, y2, BlsScalar::zero(), None);
        // x1 * x2
        let x1_x2 =
            composer.mul(BlsScalar::one(), x1, x2, BlsScalar::zero(), None);
        // d x1x2 * y1y2
        let d_x1_x2_y1_y2 =
            composer.mul(EDWARDS_D, x1_x2, y1_y2, BlsScalar::zero(), None);

        // x1y2 + y1x2
        let x_numerator = composer.add(
            (BlsScalar::one(), x1_y2),
            (BlsScalar::one(), y1_x2),
            BlsScalar::zero(),
            None,
        );

        // y1y2 - a * x1x2 (a=-1) => y1y2 + x1x2
        let y_numerator = composer.add(
            (BlsScalar::one(), y1_y2),
            (BlsScalar::one(), x1_x2),
            BlsScalar::zero(),
            None,
        );

        // 1 + dx1x2y1y2
        let x_denominator = composer.add(
            (BlsScalar::one(), d_x1_x2_y1_y2),
            (BlsScalar::zero(), composer.zero_var),
            BlsScalar::one(),
            None,
        );

        // Compute the inverse
        let inv_x_denom = composer
            .variables
            .get(&x_denominator)
            .unwrap()
            .invert()
            .unwrap();
        let inv_x_denom = composer.add_input(inv_x_denom);

        // Assert that we actually have the inverse
        // inv_x * x = 1
        composer.mul_gate(
            x_denominator,
            inv_x_denom,
            composer.zero_var,
            BlsScalar::one(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            None,
        );

        // 1 - dx1x2y1y2
        let y_denominator = composer.add(
            (-BlsScalar::one(), d_x1_x2_y1_y2),
            (BlsScalar::zero(), composer.zero_var),
            BlsScalar::one(),
            None,
        );
        let inv_y_denom = composer
            .variables
            .get(&y_denominator)
            .unwrap()
            .invert()
            .unwrap();
        let inv_y_denom = composer.add_input(inv_y_denom);
        // Assert that we actually have the inverse
        // inv_y * y = 1
        composer.mul_gate(
            y_denominator,
            inv_y_denom,
            composer.zero_var,
            BlsScalar::one(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            None,
        );

        // We can now use the inverses

        let x_3 = composer.mul(
            BlsScalar::one(),
            inv_x_denom,
            x_numerator,
            BlsScalar::zero(),
            None,
        );
        let y_3 = composer.mul(
            BlsScalar::one(),
            inv_y_denom,
            y_numerator,
            BlsScalar::zero(),
            None,
        );

        Point { x: x_3, y: y_3 }
    }
}

// XXX: Should we put these as methods on the point struct instead?
// Rationale, they only apply to points, whereas methods on the composer apply
// generally to Variables
impl StandardComposer {
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
                    point_a.conditional_select(composer, bit_1, point_b);

                composer.assert_equal_point(point_a, choice);

                let choice =
                    point_a.conditional_select(composer, bit_0, point_b);
                composer.assert_equal_point(point_b, choice);
            },
            32,
        );
        assert!(res.is_ok());
    }
}
