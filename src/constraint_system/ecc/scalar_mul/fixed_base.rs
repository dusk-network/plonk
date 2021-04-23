// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::ecc::curve_addition::fixed_base_gate::WnafRound;
use crate::constraint_system::ecc::Point;
use crate::constraint_system::{variable::Variable, StandardComposer};
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};

fn compute_wnaf_point_multiples(
    generator: JubJubExtended,
    num_bits: usize,
) -> Vec<JubJubAffine> {
    assert!(generator.is_prime_order().unwrap_u8() == 1);

    let mut multiples = vec![JubJubExtended::default(); num_bits];
    multiples[0] = generator;
    for i in 1..num_bits {
        multiples[i] = multiples[i - 1].double();
    }

    dusk_jubjub::batch_normalize(&mut multiples).collect()
}

impl StandardComposer {
    /// Adds an elliptic curve Scalar multiplication gate to the circuit
    /// description.
    ///
    /// # Note
    /// This function is optimized for fixed base ops **ONLY** and therefore,
    /// the **ONLY** `generator` inputs that should be passed to this
    /// function as inputs are [`dusk_jubjub::GENERATOR`] or
    /// [`dusk_jubjub::GENERATOR_NUMS`].
    pub fn fixed_base_scalar_mul(
        &mut self,
        jubjub_scalar: Variable,
        generator: JubJubExtended,
    ) -> Point {
        // XXX: we can slice off 3 bits from the top of wnaf, since F_r prime
        // has 252 bits. XXX :We can also move to base4 and have half
        // the number of gates since wnaf adjacent entries product is
        // zero, we will not go over the specified amount
        let num_bits = 256;

        // compute 2^iG
        let mut point_multiples =
            compute_wnaf_point_multiples(generator, num_bits);
        point_multiples.reverse();

        // Fetch the raw scalar value as bls scalar, then convert to a jubjub
        // scalar XXX: Not very Tidy, impl From function in JubJub
        let raw_bls_scalar = self.variables.get(&jubjub_scalar).unwrap();
        let raw_jubjub_scalar =
            JubJubScalar::from_bytes(&raw_bls_scalar.to_bytes()).unwrap();

        // Convert scalar to wnaf_2(k)
        let wnaf_entries = raw_jubjub_scalar.compute_windowed_naf(2);
        assert_eq!(wnaf_entries.len(), num_bits);

        // Initialise the accumulators
        let mut scalar_acc = vec![BlsScalar::zero()];
        let mut point_acc = vec![JubJubAffine::identity()];

        // Auxillary point to help with checks on the backend
        let mut xy_alphas = Vec::new();

        // Load values into accumulators based on wnaf entries
        for (i, entry) in wnaf_entries.iter().rev().enumerate() {
            // Based on the WNAF, we decide what scalar and point to add
            let (scalar_to_add, point_to_add) = match entry {
            0 => { (BlsScalar::zero(), JubJubAffine::identity())},
            -1 => {(BlsScalar::one().neg(), -point_multiples[i])},
            1 => {(BlsScalar::one(), point_multiples[i])},
            _ => unreachable!("Currently WNAF_2(k) is supported. The possible values are 1, -1 and 0. Current entry is {}", entry),
        };

            let prev_accumulator = BlsScalar::from(2u64) * scalar_acc[i];
            scalar_acc.push(prev_accumulator + scalar_to_add);
            point_acc.push(
                (JubJubExtended::from(point_acc[i])
                    + JubJubExtended::from(point_to_add))
                .into(),
            );

            let x_alpha = point_to_add.get_x();
            let y_alpha = point_to_add.get_y();

            xy_alphas.push(x_alpha * y_alpha);
        }

        for i in 0..num_bits {
            let acc_x = self.add_input(point_acc[i].get_x());
            let acc_y = self.add_input(point_acc[i].get_y());

            let accumulated_bit = self.add_input(scalar_acc[i]);

            // We constrain the point accumulator to start from the Identity
            // point and the Scalar accumulator to start from zero
            if i == 0 {
                self.constrain_to_constant(acc_x, BlsScalar::zero(), None);
                self.constrain_to_constant(acc_y, BlsScalar::one(), None);
                self.constrain_to_constant(
                    accumulated_bit,
                    BlsScalar::zero(),
                    None,
                );
            }

            let x_beta = point_multiples[i].get_x();
            let y_beta = point_multiples[i].get_y();

            let xy_alpha = self.add_input(xy_alphas[i]);

            let xy_beta = x_beta * y_beta;

            let wnaf_round = WnafRound {
                acc_x,
                acc_y,
                accumulated_bit,
                xy_alpha,
                x_beta,
                y_beta,
                xy_beta,
            };

            self.fixed_group_add(wnaf_round);
        }

        // Add last gate, but do not activate it for ECC
        // It is for use with the previous gate
        let acc_x = self.add_input(point_acc[num_bits].get_x());
        let acc_y = self.add_input(point_acc[num_bits].get_y());
        let xy_alpha = self.zero_var;
        let last_accumulated_bit = self.add_input(scalar_acc[num_bits]);

        self.big_add_gate(
            acc_x,
            acc_y,
            xy_alpha,
            Some(last_accumulated_bit),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // Constrain the last element in the accumulator to be equal to the
        // input jubjub scalar
        self.assert_equal(last_accumulated_bit, jubjub_scalar);

        Point { x: acc_x, y: acc_y }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::helper::*;
    use dusk_jubjub::GENERATOR_EXTENDED;

    #[test]
    fn test_ecc_constraint() {
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
                    (GENERATOR_EXTENDED * scalar).into();

                let point_scalar = composer
                    .fixed_base_scalar_mul(secret_scalar, GENERATOR_EXTENDED);

                composer
                    .assert_equal_public_point(point_scalar, expected_point);
            },
            600,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_ecc_constraint_zero() {
        let res = gadget_tester(
            |composer| {
                let scalar = JubJubScalar::zero();
                let bls_scalar =
                    BlsScalar::from_bytes(&scalar.to_bytes()).unwrap();
                let secret_scalar = composer.add_input(bls_scalar);

                let expected_point: JubJubAffine =
                    (GENERATOR_EXTENDED * scalar).into();

                let point_scalar = composer
                    .fixed_base_scalar_mul(secret_scalar, GENERATOR_EXTENDED);

                composer
                    .assert_equal_public_point(point_scalar, expected_point);
            },
            600,
        );
        assert!(res.is_ok());
    }
    #[test]
    fn test_ecc_constraint_should_fail() {
        let res = gadget_tester(
            |composer| {
                let scalar = JubJubScalar::from(100u64);
                let bls_scalar =
                    BlsScalar::from_bytes(&scalar.to_bytes()).unwrap();
                let secret_scalar = composer.add_input(bls_scalar);
                // Fails because we are not multiplying by the GENERATOR, it is
                // double

                let double_gen = GENERATOR_EXTENDED.double();

                let expected_point: JubJubAffine = (double_gen * scalar).into();

                let point_scalar = composer
                    .fixed_base_scalar_mul(secret_scalar, GENERATOR_EXTENDED);

                composer
                    .assert_equal_public_point(point_scalar, expected_point);
            },
            600,
        );

        assert!(res.is_err());
    }
    #[test]
    fn test_point_addition() {
        let res = gadget_tester(
            |composer| {
                let point_a = GENERATOR_EXTENDED;
                let point_b = point_a.double();
                let expected_point = point_a + point_b;

                let affine_point_a: JubJubAffine = point_a.into();
                let affine_point_b: JubJubAffine = point_b.into();
                let affine_expected_point: JubJubAffine = expected_point.into();

                let var_point_a_x = composer.add_input(affine_point_a.get_x());
                let var_point_a_y = composer.add_input(affine_point_a.get_y());
                let point_a = Point {
                    x: var_point_a_x,
                    y: var_point_a_y,
                };
                let var_point_b_x = composer.add_input(affine_point_b.get_x());
                let var_point_b_y = composer.add_input(affine_point_b.get_y());
                let point_b = Point {
                    x: var_point_b_x,
                    y: var_point_b_y,
                };
                let new_point = composer.point_addition_gate(point_a, point_b);

                composer.assert_equal_public_point(
                    new_point,
                    affine_expected_point,
                );
            },
            600,
        );

        assert!(res.is_ok());
    }
    #[test]
    #[allow(non_snake_case)]
    fn test_pedersen_hash() {
        let res = gadget_tester(
            |composer| {
                // First component
                let scalar_a = JubJubScalar::from(112233u64);
                let bls_scalar =
                    BlsScalar::from_bytes(&scalar_a.to_bytes()).unwrap();
                let secret_scalar_a = composer.add_input(bls_scalar);
                let point_a = GENERATOR_EXTENDED;
                let c_a: JubJubAffine = (point_a * scalar_a).into();

                // Second component
                let scalar_b = JubJubScalar::from(445566u64);
                let bls_scalar =
                    BlsScalar::from_bytes(&scalar_b.to_bytes()).unwrap();
                let secret_scalar_b = composer.add_input(bls_scalar);
                let point_b = point_a.double() + point_a;
                let c_b: JubJubAffine = (point_b * scalar_b).into();

                // Expected pedersen hash
                let expected_point: JubJubAffine =
                    (point_a * scalar_a + point_b * scalar_b).into();

                // To check this pedersen commitment, we will need to do:
                // - Two scalar multiplications
                // - One curve addition
                //
                // Scalar multiplications
                let aG =
                    composer.fixed_base_scalar_mul(secret_scalar_a, point_a);
                let bH =
                    composer.fixed_base_scalar_mul(secret_scalar_b, point_b);

                // Depending on the context, one can check if the resulting aG
                // and bH are as expected
                //
                composer.assert_equal_public_point(aG, c_a);
                composer.assert_equal_public_point(bH, c_b);

                // Curve addition
                let commitment = composer.point_addition_gate(aG, bH);

                // Add final constraints to ensure that the commitment that we
                // computed is equal to the public point
                composer.assert_equal_public_point(commitment, expected_point);
            },
            1024,
        );
        assert!(res.is_ok());
    }
    #[test]
    #[allow(non_snake_case)]
    fn test_pedersen_balance() {
        let res = gadget_tester(
            |composer| {
                // First component
                let scalar_a = JubJubScalar::from(25u64);
                let bls_scalar_a =
                    BlsScalar::from_bytes(&scalar_a.to_bytes()).unwrap();
                let secret_scalar_a = composer.add_input(bls_scalar_a);
                // Second component
                let scalar_b = JubJubScalar::from(30u64);
                let bls_scalar_b =
                    BlsScalar::from_bytes(&scalar_b.to_bytes()).unwrap();
                let secret_scalar_b = composer.add_input(bls_scalar_b);
                // Third component
                let scalar_c = JubJubScalar::from(10u64);
                let bls_scalar_c =
                    BlsScalar::from_bytes(&scalar_c.to_bytes()).unwrap();
                let secret_scalar_c = composer.add_input(bls_scalar_c);
                // Fourth component
                let scalar_d = JubJubScalar::from(45u64);
                let bls_scalar_d =
                    BlsScalar::from_bytes(&scalar_d.to_bytes()).unwrap();
                let secret_scalar_d = composer.add_input(bls_scalar_d);

                let gen = GENERATOR_EXTENDED;
                let expected_lhs: JubJubAffine =
                    (gen * (scalar_a + scalar_b)).into();
                let expected_rhs: JubJubAffine =
                    (gen * (scalar_c + scalar_d)).into();

                let P1 = composer.fixed_base_scalar_mul(secret_scalar_a, gen);
                let P2 = composer.fixed_base_scalar_mul(secret_scalar_b, gen);
                let P3 = composer.fixed_base_scalar_mul(secret_scalar_c, gen);
                let P4 = composer.fixed_base_scalar_mul(secret_scalar_d, gen);

                let commitment_a = composer.point_addition_gate(P1, P2);
                let commitment_b = composer.point_addition_gate(P3, P4);

                composer.assert_equal_point(commitment_a, commitment_b);

                composer.assert_equal_public_point(commitment_a, expected_lhs);
                composer.assert_equal_public_point(commitment_b, expected_rhs);
            },
            2048,
        );
        assert!(res.is_ok());
    }
}
