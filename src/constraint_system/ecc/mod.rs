/// Curve addition gate
pub mod curve_addition;
/// Gates related to scalar multiplication
pub mod scalar_mul;

use crate::constraint_system::{variable::Variable, StandardComposer};
use dusk_bls12_381::Scalar;
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
        let one = composer.add_witness_to_circuit_description(Scalar::one());
        Point {
            x: composer.zero_var,
            y: one,
        }
    }

    /// Converts an AffinePoint into a constraint system Point
    /// without constraining the values
    pub fn from_private_affine(
        composer: &mut StandardComposer,
        affine: dusk_jubjub::AffinePoint,
    ) -> Point {
        let x = composer.add_input(affine.get_x());
        let y = composer.add_input(affine.get_y());
        Point { x, y }
    }
    /// Converts an AffinePoint into a constraint system Point
    /// without constraining the values
    pub fn from_public_affine(
        composer: &mut StandardComposer,
        affine: dusk_jubjub::AffinePoint,
    ) -> Point {
        let point = Point::from_private_affine(composer, affine);
        composer.constrain_to_constant(point.x, Scalar::zero(), -affine.get_x());
        composer.constrain_to_constant(point.y, Scalar::zero(), -affine.get_y());

        point
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
    pub fn add(&self, composer: &mut StandardComposer, point_b: Point) -> Point {
        self.slow_add(composer, point_b)
    }

    /// Adds two curve points together using arithmetic gates
    pub fn slow_add(&self, composer: &mut StandardComposer, point_b: Point) -> Point {
        let x1 = self.x;
        let y1 = self.y;

        let x2 = point_b.x;
        let y2 = point_b.y;

        // x1 * y2
        let x1_y2 = composer.mul(Scalar::one(), x1, y2, Scalar::zero(), Scalar::zero());
        // y1 * x2
        let y1_x2 = composer.mul(Scalar::one(), y1, x2, Scalar::zero(), Scalar::zero());
        // y1 * y2
        let y1_y2 = composer.mul(Scalar::one(), y1, y2, Scalar::zero(), Scalar::zero());
        // x1 * x2
        let x1_x2 = composer.mul(Scalar::one(), x1, x2, Scalar::zero(), Scalar::zero());
        // d x1x2 * y1y2
        let d_x1_x2_y1_y2 = composer.mul(EDWARDS_D, x1_x2, y1_y2, Scalar::zero(), Scalar::zero());

        // x1y2 + y1x2
        let x_numerator = composer.add(
            (Scalar::one(), x1_y2),
            (Scalar::one(), y1_x2),
            Scalar::zero(),
            Scalar::zero(),
        );

        // y1y2 - a * x1x2 (a=-1) => y1y2 + x1x2
        let y_numerator = composer.add(
            (Scalar::one(), y1_y2),
            (Scalar::one(), x1_x2),
            Scalar::zero(),
            Scalar::zero(),
        );

        // 1 + dx1x2y1y2
        let x_denominator = composer.add(
            (Scalar::one(), d_x1_x2_y1_y2),
            (Scalar::zero(), composer.zero_var),
            Scalar::one(),
            Scalar::zero(),
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
            Scalar::one(),
            Scalar::zero(),
            -Scalar::one(),
            Scalar::zero(),
        );

        // 1 - dx1x2y1y2
        let y_denominator = composer.add(
            (-Scalar::one(), d_x1_x2_y1_y2),
            (Scalar::zero(), composer.zero_var),
            Scalar::one(),
            Scalar::zero(),
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
            Scalar::one(),
            Scalar::zero(),
            -Scalar::one(),
            Scalar::zero(),
        );

        // We can now use the inverses

        let x_3 = composer.mul(
            Scalar::one(),
            inv_x_denom,
            x_numerator,
            Scalar::zero(),
            Scalar::zero(),
        );
        let y_3 = composer.mul(
            Scalar::one(),
            inv_y_denom,
            y_numerator,
            Scalar::zero(),
            Scalar::zero(),
        );

        Point { x: x_3, y: y_3 }
    }
}

// XXX: Should we put these as methods on the point struct instead?
// Rationale, they only apply to points, whereas methods on the composer apply generally to Variables
impl StandardComposer {
    /// Asserts that a point in the circuit is equal to a known public point
    pub fn assert_equal_public_point(
        &mut self,
        point: Point,
        public_point: dusk_jubjub::AffinePoint,
    ) {
        self.constrain_to_constant(point.x, Scalar::zero(), -public_point.get_x());
        self.constrain_to_constant(point.y, Scalar::zero(), -public_point.get_y());
    }
    /// Asserts that a point in the circuit is equal to another point in the circuit
    pub fn assert_equal_point(&mut self, point_a: Point, point_b: Point) {
        self.assert_equal(point_a.x, point_b.x);
        self.assert_equal(point_b.y, point_b.y);
    }
}
