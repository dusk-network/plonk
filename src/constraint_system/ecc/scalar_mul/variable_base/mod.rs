// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::ecc::{Point, PointScalar};
use crate::constraint_system::{variable::Variable, StandardComposer};
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;

/// Computes a BlsScalar multiplication with the input scalar and a chosen
/// generator
pub fn variable_base_scalar_mul(
    composer: &mut StandardComposer,
    jubjub_var: Variable,
    point: Point,
) -> PointScalar {
    // Turn scalar into bits
    let raw_bls_scalar = *composer.variables.get(&jubjub_var).unwrap();
    let scalar_bits_var =
        scalar_decomposition(composer, jubjub_var, raw_bls_scalar);

    let identity = Point::identity(composer);
    let mut result = identity;

    for bit in scalar_bits_var.into_iter().rev() {
        result = result.fast_add(composer, result);
        let point_to_add = conditional_select_identity(composer, bit, point);
        result = result.fast_add(composer, point_to_add);
    }

    PointScalar {
        point: result,
        scalar: jubjub_var,
    }
}

/// If bit == 0, then return zero else return value
/// This is the polynomial f(x) = x * a
/// Where x is the bit
fn conditional_select_zero(
    composer: &mut StandardComposer,
    bit: Variable,
    value: Variable,
) -> Variable {
    // returns bit * value
    composer.mul(BlsScalar::one(), bit, value, BlsScalar::zero(), None)
}
/// If bit == 0, then return 1 else return value
/// This is the polynomial f(x) = 1 - x + xa
/// Where x is the bit
fn conditional_select_one(
    composer: &mut StandardComposer,
    bit: Variable,
    value: Variable,
) -> Variable {
    let value_scalar = composer.variables.get(&value).unwrap();
    let bit_scalar = composer.variables.get(&bit).unwrap();

    let f_x_scalar =
        BlsScalar::one() - bit_scalar + (bit_scalar * value_scalar);
    let f_x = composer.add_input(f_x_scalar);

    composer.poly_gate(
        bit,
        value,
        f_x,
        BlsScalar::one(),
        -BlsScalar::one(),
        BlsScalar::zero(),
        -BlsScalar::one(),
        BlsScalar::one(),
        None,
    );

    f_x
}

// If bit == 0 choose identity, if bit == 1 choose point_b
fn conditional_select_identity(
    composer: &mut StandardComposer,
    bit: Variable,
    point_b: Point,
) -> Point {
    let x = conditional_select_zero(composer, bit, *point_b.x());
    let y = conditional_select_one(composer, bit, *point_b.y());

    Point { x, y }
}

fn scalar_decomposition(
    composer: &mut StandardComposer,
    witness_var: Variable,
    witness_scalar: BlsScalar,
) -> Vec<Variable> {
    // Decompose the bits
    let scalar_bits = scalar_to_bits(&witness_scalar);

    // Add all the bits into the composer
    let scalar_bits_var: Vec<Variable> = scalar_bits
        .iter()
        .map(|bit| composer.add_input(BlsScalar::from(*bit as u64)))
        .collect();

    // Take the first 252 bits
    let scalar_bits_var = scalar_bits_var[0..252].to_vec();

    // Now ensure that the bits correctly accumulate to the witness given
    let mut accumulator_var = composer.zero_var;
    let mut accumulator_scalar = BlsScalar::zero();

    for (power, bit) in scalar_bits_var.iter().enumerate() {
        composer.boolean_gate(*bit);

        let two_pow = BlsScalar::pow_of_2(power as u64);

        let q_l_a = (two_pow, *bit);
        let q_r_b = (BlsScalar::one(), accumulator_var);
        let q_c = BlsScalar::zero();

        accumulator_var = composer.add(q_l_a, q_r_b, q_c, None);

        accumulator_scalar +=
            two_pow * BlsScalar::from(scalar_bits[power] as u64);
    }
    composer.assert_equal(accumulator_var, witness_var);

    scalar_bits_var
}

fn scalar_to_bits(scalar: &BlsScalar) -> [u8; 256] {
    let mut res = [0u8; 256];
    let bytes = scalar.to_bytes();
    for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
        bits.iter_mut()
            .enumerate()
            .for_each(|(i, bit)| *bit = (byte >> i) & 1)
    }
    res
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::helper::*;
    use dusk_bls12_381::BlsScalar;
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

                let point = Point::from_private_affine(composer, GENERATOR);

                let point_scalar =
                    variable_base_scalar_mul(composer, secret_scalar, point);

                composer.assert_equal_public_point(
                    point_scalar.into(),
                    expected_point,
                );
            },
            4096,
        );
        assert!(res.is_ok());
    }
}
