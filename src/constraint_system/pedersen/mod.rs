/// ECC gate
pub mod ecc;

use crate::constraint_system::variable::Variable;
use crate::constraint_system::StandardComposer;
use dusk_bls12_381::Scalar as BlsScalar;
use ecc::WnafRound;
use jubjub::Fr as JubJubScalar;
use jubjub::{AffinePoint, ExtendedPoint};

/// The result of a scalar multiplication
#[derive(Debug)]
pub struct PointScalar {
    base_x: Variable,
    base_y: Variable,
    scalar: Variable,
}

fn compute_wnaf_point_multiples(generator: ExtendedPoint, num_bits: usize) -> Vec<AffinePoint> {
    let mut multiples = vec![ExtendedPoint::default(); num_bits];
    multiples[0] = generator;
    for i in 1..num_bits {
        multiples[i] = multiples[i - 1].double();
    }

    jubjub::batch_normalize(&mut multiples).collect()
}

use jubjub::Fq;
fn edwards_d() -> Fq {
    let num = Fq::from(10240);
    let den = Fq::from(10241);
    -(num * den.invert().unwrap())
}

/// Adds two curve points together
pub fn curve_addition(
    composer: &mut StandardComposer,
    point_a: (Variable, Variable),
    point_b: (Variable, Variable),
) -> (Variable, Variable) {
    let x1 = point_a.0;
    let y1 = point_a.1;

    let x2 = point_b.0;
    let y2 = point_b.1;

    // x1 * y2
    let x1_y2 = composer.mul(
        BlsScalar::one(),
        x1,
        y2,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // y1 * x2
    let y1_x2 = composer.mul(
        BlsScalar::one(),
        y1,
        x2,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // y1 * y2
    let y1_y2 = composer.mul(
        BlsScalar::one(),
        y1,
        y2,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // x1 * x2
    let x1_x2 = composer.mul(
        BlsScalar::one(),
        x1,
        x2,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    // d x1x2 * y1y2
    let d_x1_x2_y1_y2 = composer.mul(
        edwards_d(),
        x1_x2,
        y1_y2,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    // x1y2 + y1x2
    let x_numerator = composer.add(
        (BlsScalar::one(), x1_y2),
        (BlsScalar::one(), y1_x2),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    // y1y2 - a * x1x2 (a=-1) => y1y2 + x1x2
    let y_numerator = composer.add(
        (BlsScalar::one(), y1_y2),
        (BlsScalar::one(), x1_x2),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    // 1 + dx1x2y1y2
    let x_denominator = composer.add(
        (BlsScalar::one(), d_x1_x2_y1_y2),
        (BlsScalar::zero(), composer.zero_var),
        BlsScalar::one(),
        BlsScalar::zero(),
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
        BlsScalar::zero(),
    );

    // 1 - dx1x2y1y2
    let y_denominator = composer.add(
        (-BlsScalar::one(), d_x1_x2_y1_y2),
        (BlsScalar::zero(), composer.zero_var),
        BlsScalar::one(),
        BlsScalar::zero(),
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
        BlsScalar::zero(),
    );

    // We can now use the inverses

    let x_3 = composer.mul(
        BlsScalar::one(),
        inv_x_denom,
        x_numerator,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );
    let y_3 = composer.mul(
        BlsScalar::one(),
        inv_y_denom,
        y_numerator,
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    (x_3, y_3)
}

/// Computes a Scalar multiplication with the input scalar and the fixed generator
pub fn fixed_based_scalar_mul(
    composer: &mut StandardComposer,
    jubjub_scalar: Variable,
    generator: ExtendedPoint,
) -> PointScalar {
    // XXX: we can slice off 3 bits from the top of wnaf, since F_r prime has 252 bits.
    // XXX :We can also move to base4 and have half the number of gates since wnaf adjacent entries product is zero, we will not go over the specified amount
    let num_bits = 256;

    // compute 2^iG
    let mut point_multiples = compute_wnaf_point_multiples(generator, num_bits);
    point_multiples.reverse();

    // Fetch the raw scalar value as bls scalar, then convert to a jubjub scalar
    // XXX: Not very Tidy, impl From function in JubJub
    let raw_bls_scalar = composer.variables.get(&jubjub_scalar).unwrap();
    let raw_jubjub_scalar = JubJubScalar::from_bytes(&raw_bls_scalar.to_bytes()).unwrap();

    // Convert scalar to wnaf_2(k)
    let wnaf_entries = raw_jubjub_scalar.compute_windowed_naf(2);
    assert_eq!(wnaf_entries.len(), num_bits);

    // Initialise the accumulators
    let mut scalar_acc: Vec<BlsScalar> = Vec::new();
    scalar_acc.push(BlsScalar::zero());
    let mut point_acc: Vec<AffinePoint> = Vec::new();
    point_acc.push(AffinePoint::identity());

    // Auxillary point to help with checks on the backend
    let mut xy_alphas = Vec::new();

    // Load values into accumulators based on wnaf entries
    for (i, entry) in wnaf_entries.iter().rev().enumerate() {
        // Based on the WNAF, we decide what scalar and point to add
        let (scalar_to_add, point_to_add) = match entry {
            0 => { (BlsScalar::zero(), AffinePoint::identity())},
            -1 => {(BlsScalar::one().neg(), -point_multiples[i])},
            1 => {(BlsScalar::one(), point_multiples[i])},
            _ => unreachable!("Currently WNAF_2(k) is supported. The possible values are 1, -1 and 0. Current entry is {}", entry),
        };

        let prev_accumulator = BlsScalar::from(2u64) * scalar_acc[i];
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

        let accumulated_bit = composer.add_input(scalar_acc[i]);

        // We constrain the point accumulator to start from the Identity point
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
    let last_accumulated_bit = composer.add_input(scalar_acc[num_bits]);

    composer.big_add_gate(
        acc_x,
        acc_y,
        xy_alpha,
        Some(last_accumulated_bit),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    // Constrain the last element in the accumulator to be equal to the input jubjub scalar
    composer.assert_equal(last_accumulated_bit, jubjub_scalar);

    PointScalar {
        base_x: acc_x,
        base_y: acc_y,
        scalar: last_accumulated_bit,
    }
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use super::*;
    use jubjub::GENERATOR;
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

                let point_scalar =
                    fixed_based_scalar_mul(composer, secret_scalar, GENERATOR.into());

                composer
                    .assert_equal_point((point_scalar.base_x, point_scalar.base_y), expected_point);
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

                let point_scalar =
                    fixed_based_scalar_mul(composer, secret_scalar, GENERATOR.into());

                composer
                    .assert_equal_point((point_scalar.base_x, point_scalar.base_y), expected_point);
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

                let point_scalar =
                    fixed_based_scalar_mul(composer, secret_scalar, GENERATOR.into());
                composer.assert_equal(expected_x, point_scalar.base_x);
                composer.assert_equal(expected_y, point_scalar.base_y);
            },
            600,
        );

        assert!(res.is_err());
    }
    #[test]
    fn test_point_addition() {
        let res = gadget_tester(
            |composer| {
                let point_a = ExtendedPoint::from(GENERATOR);
                let point_b = point_a.double();
                let expected_point = point_a + point_b;

                let affine_point_a: AffinePoint = point_a.into();
                let affine_point_b: AffinePoint = point_b.into();
                let affine_expected_point: AffinePoint = expected_point.into();

                let var_point_a_x = composer.add_input(affine_point_a.get_x());
                let var_point_a_y = composer.add_input(affine_point_a.get_y());
                let var_point_b_x = composer.add_input(affine_point_b.get_x());
                let var_point_b_y = composer.add_input(affine_point_b.get_y());

                let new_point = curve_addition(
                    composer,
                    (var_point_a_x, var_point_a_y),
                    (var_point_b_x, var_point_b_y),
                );

                composer.assert_equal_point(new_point, affine_expected_point);
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
                let bls_scalar = BlsScalar::from_bytes(&scalar_a.to_bytes()).unwrap();
                let secret_scalar_a = composer.add_input(bls_scalar);
                let point_a = ExtendedPoint::from(GENERATOR);
                let c_a: AffinePoint = (point_a * scalar_a).into();

                // Second component
                let scalar_b = JubJubScalar::from(445566u64);
                let bls_scalar = BlsScalar::from_bytes(&scalar_b.to_bytes()).unwrap();
                let secret_scalar_b = composer.add_input(bls_scalar);
                let point_b = point_a.double() + point_a;
                let c_b: AffinePoint = (point_b * scalar_b).into();

                // Expected pedersen hash
                let expected_point: AffinePoint = (point_a * scalar_a + point_b * scalar_b).into();

                // To check this pedersen commitment, we will need to do:
                // - Two scalar multiplications
                // - One curve addition
                //
                // Scalar multiplications
                let aG = fixed_based_scalar_mul(composer, secret_scalar_a, point_a);
                let bH = fixed_based_scalar_mul(composer, secret_scalar_b, point_b);

                // Depending on the context, one can check if the resulting aG and bH are as expected
                //
                composer.constrain_to_constant(aG.base_x, BlsScalar::zero(), -c_a.get_x());
                composer.constrain_to_constant(aG.base_y, BlsScalar::zero(), -c_a.get_y());
                composer.constrain_to_constant(bH.base_x, BlsScalar::zero(), -c_b.get_x());
                composer.constrain_to_constant(bH.base_y, BlsScalar::zero(), -c_b.get_y());
                // Curve addition
                let commitment =
                    curve_addition(composer, (aG.base_x, aG.base_y), (bH.base_x, bH.base_y));

                // Add final constraints to ensure that the commitment that we computed is equal to the public point
                composer.assert_equal_point(commitment, expected_point);
            },
            1024,
        );
        assert!(res.is_ok());
    }
}
