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
    /// Returns thes identity point.
    pub fn identity(composer: &mut TurboComposer) -> WitnessPoint {
        let one = composer.append_circuit_constant(BlsScalar::one());
        WitnessPoint {
            x: composer.zero(),
            y: one,
        }
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

impl TurboComposer {
    /// Converts an JubJubAffine into a constraint system WitnessPoint
    /// without constraining the values
    pub fn add_affine(&mut self, affine: JubJubAffine) -> WitnessPoint {
        let x = self.append_witness(affine.get_x());
        let y = self.append_witness(affine.get_y());
        WitnessPoint { x, y }
    }

    /// Converts an JubJubAffine into a constraint system WitnessPoint
    /// without constraining the values
    pub fn add_public_affine(
        &mut self,
        affine: dusk_jubjub::JubJubAffine,
    ) -> WitnessPoint {
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
    ) -> WitnessPoint {
        // Not using individual gates because one of these may be zero
        let x = self.append_circuit_constant(affine.get_x());
        let y = self.append_circuit_constant(affine.get_y());

        WitnessPoint { x, y }
    }

    /// Asserts that a [`WitnessPoint`] in the circuit is equal to a known
    /// public point.
    pub fn assert_equal_public_point(
        &mut self,
        point: WitnessPoint,
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
    pub fn assert_equal_point(
        &mut self,
        point_a: WitnessPoint,
        point_b: WitnessPoint,
    ) {
        self.assert_equal(point_a.x, point_b.x);
        self.assert_equal(point_b.y, point_b.y);
    }

    /// Adds to the circuit description the conditional selection of the
    /// a point between two of them.
    /// bit == 1 => point_a,
    /// bit == 0 => point_b,
    ///
    /// # Note
    /// The `bit` used as input which is a
    /// [`Witness`] should had previously been constrained to be either 1 or 0
    /// using a bool constrain. See: [`TurboComposer::boolean_gate`].
    pub fn conditional_point_select(
        &mut self,
        point_a: WitnessPoint,
        point_b: WitnessPoint,
        bit: Witness,
    ) -> WitnessPoint {
        let x = self.conditional_select(bit, *point_a.x(), *point_b.x());
        let y = self.conditional_select(bit, *point_a.y(), *point_b.y());

        WitnessPoint { x, y }
    }

    /// Adds to the circuit description the conditional selection of the
    /// identity point:
    /// bit == 1 => value,
    /// bit == 0 => 1,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Witness`] should had
    /// previously been constrained to be either 1 or 0 using a bool
    /// constrain. See: [`TurboComposer::boolean_gate`].
    fn conditional_select_identity(
        &mut self,
        bit: Witness,
        point_b: WitnessPoint,
    ) -> WitnessPoint {
        let x = self.conditional_select_zero(bit, *point_b.x());
        let y = self.conditional_select_one(bit, *point_b.y());

        WitnessPoint { x, y }
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
                let bit_1 = composer.append_witness(BlsScalar::one());
                let bit_0 = composer.zero();

                let point_a = WitnessPoint::identity(composer);
                let point_b = WitnessPoint {
                    x: composer.append_witness(BlsScalar::from(10u64)),
                    y: composer.append_witness(BlsScalar::from(20u64)),
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
