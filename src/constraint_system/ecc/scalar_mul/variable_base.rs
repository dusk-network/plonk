// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::ecc::AllocatedPoint;
use crate::constraint_system::{variable::AllocatedScalar, TurboComposer};
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;

impl TurboComposer {
    /// Adds a variable-base scalar multiplication to the circuit description.
    ///
    /// # Note
    /// If you're planning to multiply always by the generator of the Scalar
    /// field, you should use [`TurboComposer::fixed_base_scalar_mul`]
    /// which is optimized for fixed_base ops.
    pub fn variable_base_scalar_mul(
        &mut self,
        jubjub_var: AllocatedScalar,
        point: AllocatedPoint,
    ) -> AllocatedPoint {
        // Turn scalar into bits
        let scalar_bits = self.scalar_decomposition(jubjub_var);

        let identity = AllocatedPoint::identity(self);
        let mut result = identity;

        for bit in scalar_bits.into_iter().rev() {
            result = self.point_addition_gate(result, result);
            let point_to_add = self.conditional_select_identity(bit, point);
            result = self.point_addition_gate(result, point_to_add);
        }

        result
    }

    fn scalar_decomposition(
        &mut self,
        witness: AllocatedScalar,
    ) -> Vec<AllocatedScalar> {
        // Decompose the bits
        let scalar_bits = self.scalar_bit_decomposition(witness);

        // Take the first 252 bits
        let scalar_bits_var = scalar_bits[..252].to_vec();

        // Now ensure that the bits correctly accumulate to the witness given
        let mut accumulator_var = self.allocated_zero();
        let mut accumulator_scalar = BlsScalar::zero();

        for (power, bit) in scalar_bits_var.iter().enumerate() {
            self.boolean_gate(*bit);

            let two_pow = BlsScalar::pow_of_2(power as u64);

            let q_l_a = (two_pow, *bit);
            let q_r_b = (BlsScalar::one(), accumulator_var);
            let q_c = BlsScalar::zero();

            accumulator_var = self.add(q_l_a, q_r_b, q_c, None);

            accumulator_scalar += two_pow * scalar_bits[power];
        }
        self.assert_equal(accumulator_var, witness);

        scalar_bits_var
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::constraint_system::helper::*;
    use dusk_bls12_381::BlsScalar;
    use dusk_bytes::Serializable;
    use dusk_jubjub::GENERATOR;
    use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
    #[test]
    fn test_var_base_scalar_mul() {
        let res = gadget_tester(
            |composer| {
                let scalar = JubJubScalar::from_bytes_wide(&[
                    182, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204,
                    147, 32, 104, 166, 0, 59, 52, 1, 1, 59, 103, 6, 169, 175,
                    51, 101, 234, 180, 125, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0,
                ]);
                let bls_scalar =
                    BlsScalar::from_bytes(&scalar.to_bytes()).unwrap();
                let secret_scalar = composer.add_input(bls_scalar);

                let expected_point: JubJubAffine =
                    (JubJubExtended::from(GENERATOR) * scalar).into();

                let point = composer.add_affine(GENERATOR);

                let point_scalar =
                    composer.variable_base_scalar_mul(secret_scalar, point);

                composer
                    .assert_equal_public_point(point_scalar, expected_point);
            },
            4096,
        );
        assert!(res.is_ok());
    }
}
