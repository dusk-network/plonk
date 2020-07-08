/// ECC gate
pub mod ecc;
mod weistrass;

use crate::constraint_system::variable::Variable;
use crate::constraint_system::StandardComposer;
use dusk_bls12_381::Scalar as BlsScalar;
use ecc::WnafRound;
use jubjub::Fr as JubJubScalar;
use jubjub::{AffinePoint, ExtendedPoint, GENERATOR};

/// The result of a scalar multiplication
#[derive(Debug)]
pub struct PointScalar {
    base_x: Variable,
    base_y: Variable,
    scalar: Variable,
}

fn compute_wnaf_point_multiples(generator: AffinePoint, num_bits: usize) -> Vec<AffinePoint> {
    let mut multiples = vec![AffinePoint::default(); num_bits];
    multiples[0] = generator;
    for i in 1..num_bits {
        let mut accumulator = ExtendedPoint::from(multiples[i - 1]);
        accumulator = accumulator.double();

        multiples[i] = (accumulator).into();
    }

    multiples
}

/// Computes a Scalar multiplication with the input scalar and the fixed generator
pub fn new_fixed_based_scalar_mul(
    composer: &mut StandardComposer,
    jubjub_scalar: Variable,
) -> PointScalar {
    // First we get the generator
    let generator = GENERATOR;
    assert!(generator.is_prime_order().unwrap_u8() == 1);

    // XXX: we can slice off 3 bits from the top, since F_r prime has 252 bits.
    // XXX :We can also move to base4 and have half the number of gates since wnaf adjacent entries product is zero, we will not go over the specified amount
    let num_bits = 256;

    // compute 2^iG
    let mut point_multiples = compute_wnaf_point_multiples(generator, num_bits);
    point_multiples.reverse();

    // Fetch the raw scalar value as bls scalar, then convert to a jubjub scalar
    // XXX: Not very Tidy
    let raw_bls_scalar = composer.variables.get(&jubjub_scalar).unwrap();
    let raw_jubjub_scalar = JubJubScalar::from_bytes(&raw_bls_scalar.to_bytes()).unwrap();

    // Convert scalar to wnaf_2(k)
    let wnaf_entries = raw_jubjub_scalar.compute_windowed_naf(2);
    assert_eq!(wnaf_entries.len(), num_bits);

    // Initialise the accumulators
    let mut scalar_acc: Vec<JubJubScalar> = Vec::new();
    scalar_acc.push(JubJubScalar::zero());
    let mut point_acc: Vec<AffinePoint> = Vec::new();
    point_acc.push(AffinePoint::identity());

    // Auxillary point to help with checks on the backend
    let mut xy_alphas = Vec::new();

    // Load values into accumulators based on wnaf entries
    for (i, entry) in wnaf_entries.iter().rev().enumerate() {
        // Based on the WNAF, we decide what scalar and point to add
        let (scalar_to_add, point_to_add) = match entry {
            0 => { (JubJubScalar::zero(), AffinePoint::identity())},
            -1 => {(JubJubScalar::one().neg(), -point_multiples[i])},
            1 => {(JubJubScalar::one(), point_multiples[i])},
            _ => unreachable!("Currently WNAF_2(k) is supported. The possible values are 1, -1 and 0. Current entry is {}", entry),
        };

        let prev_accumulator = JubJubScalar::from(2u64) * scalar_acc[i];
        scalar_acc.push(prev_accumulator + scalar_to_add);
        point_acc
            .push((ExtendedPoint::from(point_acc[i]) + ExtendedPoint::from(point_to_add)).into());

        let x_alpha = point_to_add.get_x();
        let y_alpha = point_to_add.get_y();

        xy_alphas.push(x_alpha * y_alpha);
    }

    for i in 0..num_bits {
        let acc_x = composer.add_input(point_acc[i].get_x());
        let acc_y = composer.add_input(point_acc[i].get_y());

        // XXX: Not very Tidy. Convert from a JubJubScalar to a BlsScalar
        let bls_scalar = BlsScalar::from_bytes(&scalar_acc[i].to_bytes()).unwrap();
        let accumulated_bit = composer.add_input(bls_scalar);

        // We constraint the point accumulator to start from the Identity point
        // and the Scalar accumulator to start from zero
        if i == 0 {
            composer.constrain_to_constant(acc_x, BlsScalar::zero(), BlsScalar::zero());
            composer.constrain_to_constant(acc_y, BlsScalar::one(), BlsScalar::zero());
            composer.constrain_to_constant(accumulated_bit, BlsScalar::zero(), BlsScalar::zero());
        }

        let x_beta = point_multiples[i].get_x();
        let y_beta = point_multiples[i].get_y();

        let xy_alpha = composer.add_input(xy_alphas[i]);

        let wnaf_round = WnafRound {
            acc_x,
            acc_y,
            accumulated_bit,
            xy_alpha,
            x_beta,
            y_beta,
        };

        composer.new_fixed_group_add(wnaf_round);
    }

    // Add last gate, but do not activate it for ECC
    // It is for use with the previous gate
    let acc_x = composer.add_input(point_acc[num_bits].get_x());
    let acc_y = composer.add_input(point_acc[num_bits].get_y());
    let xy_alpha = composer.zero_var;
    let bls_scalar = BlsScalar::from_bytes(&scalar_acc[num_bits].to_bytes()).unwrap();
    let accumulated_bit = composer.add_input(bls_scalar);

    composer.big_add_gate(
        acc_x,
        acc_y,
        xy_alpha,
        Some(accumulated_bit),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    // Constrain the last element in the accumulator to be equal to the input jubjub scalar
    composer.assert_equal(accumulated_bit, jubjub_scalar);

    PointScalar {
        base_x: acc_x,
        base_y: acc_y,
        scalar: accumulated_bit,
    }
}

#[test]
fn new_test_ladder_compute() {
    let num_bits = 256;
    let wnaf_point = compute_wnaf_point_multiples(GENERATOR, num_bits);

    let generator = GENERATOR;

    assert_eq!(wnaf_point[0], generator);
    for i in 1..num_bits {
        let point = wnaf_point[i];

        let pow_two = JubJubScalar::from(2u64).pow(&[i as u64, 0, 0, 0]);
        let expected_point: AffinePoint = (ExtendedPoint::from(generator) * pow_two).into();

        assert_eq!(expected_point, point, "{}", i);
    }
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use super::*;
    #[test]
    fn test_ecc_constraint() {
        let res = gadget_tester(
            |composer| {
                let scalar = JubJubScalar::from_bytes_wide(&[
                    182, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166, 0,
                    59, 52, 1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,
                ]);
                let bls_scalar = BlsScalar::from_bytes(&scalar.to_bytes()).unwrap();
                let secret_scalar = composer.add_input(bls_scalar);

                let expected_point: AffinePoint = (ExtendedPoint::from(GENERATOR) * scalar).into();
                let expected_x = composer.add_input(expected_point.get_x());
                let expected_y = composer.add_input(expected_point.get_y());

                //
                let point_scalar = new_fixed_based_scalar_mul(composer, secret_scalar);
                composer.assert_equal(expected_x, point_scalar.base_x);
                composer.assert_equal(expected_y, point_scalar.base_y);
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
                let bls_scalar = BlsScalar::from_bytes(&scalar.to_bytes()).unwrap();
                let secret_scalar = composer.add_input(bls_scalar);

                let expected_point: AffinePoint = (ExtendedPoint::from(GENERATOR) * scalar).into();
                let expected_x = composer.add_input(expected_point.get_x());
                let expected_y = composer.add_input(expected_point.get_y());

                //
                let point_scalar = new_fixed_based_scalar_mul(composer, secret_scalar);
                composer.assert_equal(expected_x, point_scalar.base_x);
                composer.assert_equal(expected_y, point_scalar.base_y);
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
                let bls_scalar = BlsScalar::from_bytes(&scalar.to_bytes()).unwrap();
                let secret_scalar = composer.add_input(bls_scalar);
                // Fails because we are not multiplying by the GENERATOR

                let double_gen = ExtendedPoint::from(GENERATOR).double();

                let expected_point: AffinePoint = (double_gen * scalar).into();
                let expected_x = composer.add_input(expected_point.get_x());
                let expected_y = composer.add_input(expected_point.get_y());

                //
                let point_scalar = new_fixed_based_scalar_mul(composer, secret_scalar);
                composer.assert_equal(expected_x, point_scalar.base_x);
                composer.assert_equal(expected_y, point_scalar.base_y);
            },
            600,
        );

        assert!(res.is_err());
    }
}
