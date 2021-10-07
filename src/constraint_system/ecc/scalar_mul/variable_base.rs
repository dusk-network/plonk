// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::{TurboComposer, Witness, WitnessPoint};

impl TurboComposer {
    /// Evaluate `jubjub · point` as a [`WitnessPoint`]
    pub fn component_mul_point(
        &mut self,
        jubjub: Witness,
        point: WitnessPoint,
    ) -> WitnessPoint {
        // Turn scalar into bits
        let scalar_bits = self.component_decomposition::<252>(jubjub);

        let identity = self.append_constant_identity();
        let mut result = identity;

        for bit in scalar_bits.iter().rev() {
            result = self.component_add_point(result, result);

            let point_to_add = self.component_select_identity(*bit, point);
            result = self.component_add_point(result, point_to_add);
        }

        result
    }

    /*
    fn scalar_decomposition(&mut self, witness: Witness) -> Vec<Witness> {
        // Decompose the bits
        let scalar_bits = self.gate_decomposition(witness);

        // Take the first 252 bits
        let scalar_bits_witness = scalar_bits[..252].to_vec();

        // Now ensure that the bits correctly accumulate to the witness given
        let mut accumulator_witness = self.constant_zero();
        let mut accumulator_scalar = BlsScalar::zero();

        for (power, bit) in scalar_bits_witness.iter().enumerate() {
            self.gate_boolean(*bit);

            let two_pow = BlsScalar::pow_of_2(power as u64);

            accumulator_witness = self.gate_add(
                *bit,
                accumulator_witness,
                self.constant_zero(),
                two_pow,
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
                None,
            );

            accumulator_scalar += two_pow * self.witnesses[&scalar_bits[power]];
        }

        self.assert_equal(accumulator_witness, witness);

        scalar_bits_witness
    }
    */
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
                let secret_scalar = composer.append_witness(bls_scalar);

                let expected_point: JubJubAffine =
                    (JubJubExtended::from(GENERATOR) * scalar).into();

                let point = composer.append_point(GENERATOR);

                let point_scalar =
                    composer.component_mul_point(secret_scalar, point);

                composer
                    .assert_equal_public_point(point_scalar, expected_point);
            },
            4096,
        );
        assert!(res.is_ok());
    }
}
