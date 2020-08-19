use crate::constraint_system::ecc::{Point, PointScalar};
use crate::constraint_system::{variable::Variable, StandardComposer};
use dusk_bls12_381::Scalar;

/// Computes a Scalar multiplication with the input scalar and a chosen generator
pub fn variable_base_scalar_mul(
    composer: &mut StandardComposer,
    jubjub_var: Variable,
    point: Point,
) -> PointScalar {
    // Turn scalar into bits
    let raw_bls_scalar = composer.variables.get(&jubjub_var).unwrap().clone();
    let scalar_bits_var = scalar_decomposition(composer, jubjub_var, raw_bls_scalar);

    let identity = Point::identity(composer);
    let mut result = identity;

    for bit in scalar_bits_var.into_iter().rev() {
        result = result.fast_add(composer, result);
        let point_to_add = conditional_select_point(composer, bit, point, identity);
        result = result.fast_add(composer, point_to_add);
    }

    PointScalar {
        point: result,
        scalar: jubjub_var,
    }
}

// If bit == 1 choose point_a, if bit == 0 choose point_b
fn conditional_select_point(
    composer: &mut StandardComposer,
    bit: Variable,
    point_a: Point,
    point_b: Point,
) -> Point {
    let x = conditional_select(composer, bit, *point_a.x(), *point_b.x());
    let y = conditional_select(composer, bit, *point_a.y(), *point_b.y());

    Point { x, y }
}

// If bit == 1 choose choice_a, if bit == 0 choose choice_b
fn conditional_select(
    composer: &mut StandardComposer,
    bit: Variable,
    choice_a: Variable,
    choice_b: Variable,
) -> Variable {
    // bit * choice_a
    let bit_times_a = composer.mul(Scalar::one(), bit, choice_a, Scalar::zero(), Scalar::zero());

    // 1 - bit
    let one_min_bit = composer.add(
        (-Scalar::one(), bit),
        (Scalar::zero(), composer.zero_var),
        Scalar::one(),
        Scalar::zero(),
    );

    // (1 - bit) * b
    let one_min_bit_choice_b = composer.mul(
        Scalar::one(),
        one_min_bit,
        choice_b,
        Scalar::zero(),
        Scalar::zero(),
    );

    // [ (1 - bit) * b ] + [ bit * a ]
    let choice = composer.add(
        (Scalar::one(), one_min_bit_choice_b),
        (Scalar::one(), bit_times_a),
        Scalar::zero(),
        Scalar::zero(),
    );

    choice
}

fn scalar_decomposition(
    composer: &mut StandardComposer,
    witness_var: Variable,
    witness_scalar: Scalar,
) -> Vec<Variable> {
    // Decompose the bits
    let scalar_bits = scalar_to_bits(&witness_scalar);

    // Add all the bits into the composer
    let scalar_bits_var: Vec<Variable> = scalar_bits
        .iter()
        .map(|bit| {
            let var = composer.add_input(Scalar::from(*bit as u64));
            var
        })
        .collect();

    // Take the first 252 bits
    let scalar_bits_var = scalar_bits_var[0..252].to_vec().clone();

    // Now ensure that the bits correctly accumulate to the witness given
    let mut accumulator_var = composer.zero_var;
    let mut accumulator_scalar = Scalar::zero();

    for (power, bit) in scalar_bits_var.iter().enumerate() {
        composer.boolean_gate(*bit);

        let two_pow = Scalar::from(2).pow(&[power as u64, 0, 0, 0]);

        let q_l_a = (two_pow, *bit);
        let q_r_b = (Scalar::one(), accumulator_var);
        let q_c = Scalar::zero();
        let pi = Scalar::zero();

        accumulator_var = composer.add(q_l_a, q_r_b, q_c, pi);

        accumulator_scalar =
            accumulator_scalar + &two_pow * &Scalar::from(scalar_bits[power] as u64);
    }
    composer.assert_equal(accumulator_var, witness_var);

    scalar_bits_var
}

fn scalar_to_bits(scalar: &Scalar) -> [u8; 256] {
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
    use dusk_bls12_381::Scalar as BlsScalar;
    use dusk_jubjub::GENERATOR;
    use dusk_jubjub::{AffinePoint, ExtendedPoint, Fr as JubJubScalar};
    #[test]
    fn test_var_base_scalar_mul() {
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

                let point = Point::from_private_affine(composer, GENERATOR);

                let point_scalar = variable_base_scalar_mul(composer, secret_scalar, point);
                
                composer.assert_equal_public_point(point_scalar.into(), expected_point);
            },
            4096,
        );
        assert!(res.is_ok());
    }
    
    #[test]
    fn test_conditional_select() {
        let res = gadget_tester(
            |composer| {
                let bit_1 = composer.add_input(Scalar::one());
                let bit_0 = composer.add_input(Scalar::zero());

                let choice_a = composer.add_input(Scalar::from(10u64));
                let choice_b = composer.add_input(Scalar::from(20u64));

                let choice = conditional_select(composer, bit_1, choice_a, choice_b);
                composer.assert_equal(choice, choice_a);

                let choice = conditional_select(composer, bit_0, choice_a, choice_b);
                composer.assert_equal(choice, choice_b);
            },
            32,
        );
        assert!(res.is_ok());
    }
    #[test]
    fn test_conditional_select_point() {
        let res = gadget_tester(
            |composer| {
                let bit_1 = composer.add_input(Scalar::one());
                let bit_0 = composer.add_input(Scalar::zero());

                let point_a = Point::identity(composer);
                let point_b = Point {
                    x: composer.add_input(Scalar::from(10u64)),
                    y: composer.add_input(Scalar::from(20u64)),
                };

                let choice = conditional_select_point(composer, bit_1, point_a, point_b);

                composer.assert_equal_point(point_a, choice);

                let choice = conditional_select_point(composer, bit_0, point_a, point_b);
                composer.assert_equal_point(point_b, choice);
            },
            32,
        );
        assert!(res.is_ok());
    }
}
