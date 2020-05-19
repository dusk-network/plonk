#![allow(clippy::too_many_arguments)]

use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use dusk_bls12_381::Scalar;

/// Adds a width-3 add gate to the circuit, linking the addition of the
/// provided inputs, scaled by the selector coefficients with the output
/// provided.
pub fn add_gate(
    composer: &mut StandardComposer,
    a: Variable,
    b: Variable,
    c: Variable,
    q_l: Scalar,
    q_r: Scalar,
    q_o: Scalar,
    q_c: Scalar,
    pi: Scalar,
) -> Variable {
    big_add_gate(
        composer,
        a,
        b,
        c,
        None,
        q_l,
        q_r,
        q_o,
        Scalar::zero(),
        q_c,
        pi,
    )
}

/// Adds a width-4 add gate to the circuit and it's corresponding
/// constraint.
///
/// This type of gate is usually used when we need to have
/// the largest amount of performance and the minimum circuit-size
/// possible. Since it allows the end-user to set every selector coefficient
/// as scaling value on the gate eq.
pub fn big_add_gate(
    composer: &mut StandardComposer,
    a: Variable,
    b: Variable,
    c: Variable,
    d: Option<Variable>,
    q_l: Scalar,
    q_r: Scalar,
    q_o: Scalar,
    q_4: Scalar,
    q_c: Scalar,
    pi: Scalar,
) -> Variable {
    // Check if advice wire has a value
    let d = match d {
        Some(var) => var,
        None => composer.zero_var,
    };

    composer.w_l.push(a);
    composer.w_r.push(b);
    composer.w_o.push(c);
    composer.w_4.push(d);

    // For an add gate, q_m is zero
    composer.q_m.push(Scalar::zero());

    // Add selector vectors
    composer.q_l.push(q_l);
    composer.q_r.push(q_r);
    composer.q_o.push(q_o);
    composer.q_c.push(q_c);
    composer.q_4.push(q_4);
    composer.q_arith.push(Scalar::one());
    composer.q_range.push(Scalar::zero());
    composer.q_logic.push(Scalar::zero());

    composer.public_inputs.push(pi);

    composer.perm.add_variables_to_map(a, b, c, d, composer.n);

    composer.n += 1;

    c
}
/// Adds a width-3 add gate to the circuit linking the product of the
/// provided inputs scaled by the selector coefficient `q_m` with the output
/// provided scaled by `q_o`.
///
/// Note that this gate requires to provide the actual result of the gate
/// (output wire) since it will just add a `mul constraint` to the circuit.
pub fn mul_gate(
    composer: &mut StandardComposer,
    a: Variable,
    b: Variable,
    c: Variable,
    q_m: Scalar,
    q_o: Scalar,
    q_c: Scalar,
    pi: Scalar,
) -> Variable {
    big_mul_gate(composer, a, b, c, None, q_m, q_o, q_c, Scalar::zero(), pi)
}

/// Adds a width-4 `big_mul_gate` with the left, right and fourth inputs
/// and it's scaling factors, computing & returning the output (result)
/// `Variable` and adding the corresponding mul constraint.
///
/// This type of gate is usually used when we need to have
/// the largest amount of performance and the minimum circuit-size
/// possible. Since it allows the end-user to setup all of the selector
/// coefficients.
///
/// Forces `q_l * (w_l + w_r) + w_4 * q_4 + + q_c + PI = q_o * w_o(computed by the gate)`.
/// XXX: Maybe make these tuples instead of individual field?
pub fn big_mul_gate(
    composer: &mut StandardComposer,
    a: Variable,
    b: Variable,
    c: Variable,
    d: Option<Variable>,
    q_m: Scalar,
    q_o: Scalar,
    q_c: Scalar,
    q_4: Scalar,
    pi: Scalar,
) -> Variable {
    // Check if advice wire has a value
    let d = match d {
        Some(var) => var,
        None => composer.zero_var,
    };

    composer.w_l.push(a);
    composer.w_r.push(b);
    composer.w_o.push(c);
    composer.w_4.push(d);

    // For a mul gate q_L and q_R is zero
    composer.q_l.push(Scalar::zero());
    composer.q_r.push(Scalar::zero());

    // Add selector vectors
    composer.q_m.push(q_m);
    composer.q_o.push(q_o);
    composer.q_c.push(q_c);
    composer.q_4.push(q_4);
    composer.q_arith.push(Scalar::one());

    composer.q_range.push(Scalar::zero());
    composer.q_logic.push(Scalar::zero());

    composer.public_inputs.push(pi);

    composer.perm.add_variables_to_map(a, b, c, d, composer.n);

    composer.n += 1;

    c
}

/// Adds a `big_addition_gate` with the left and right inputs
/// and it's scaling factors, computing & returning the output (result)
/// `Variable`, and adding the corresponding addition constraint.
///
/// This type of gate is usually used when we don't need to have
/// the largest amount of performance as well as the minimum circuit-size
/// possible. Since it defaults some of the selector coeffs = 0 in order
/// to reduce the verbosity and complexity.
///
/// Forces `q_l * w_l + q_r * w_r + q_c + PI = w_o(computed by the gate)`.
pub fn add(
    composer: &mut StandardComposer,
    q_l_a: (Scalar, Variable),
    q_r_b: (Scalar, Variable),
    q_c: Scalar,
    pi: Scalar,
) -> Variable {
    big_add(composer, q_l_a, q_r_b, None, q_c, pi)
}

/// Adds a `big_addition_gate` with the left, right and fourth inputs
/// and it's scaling factors, computing & returning the output (result)
/// `Variable` and adding the corresponding addition constraint.
///
/// This type of gate is usually used when we don't need to have
/// the largest amount of performance and the minimum circuit-size
/// possible. Since it defaults some of the selector coeffs = 0 in order
/// to reduce the verbosity and complexity.
///
/// Forces `q_l * w_l + q_r * w_r + q_4 * w_4 + q_c + PI = w_o(computed by the gate)`.
pub fn big_add(
    composer: &mut StandardComposer,
    q_l_a: (Scalar, Variable),
    q_r_b: (Scalar, Variable),
    q_4_d: Option<(Scalar, Variable)>,
    q_c: Scalar,
    pi: Scalar,
) -> Variable {
    // Check if advice wire is available
    let (q_4, d) = match q_4_d {
        Some((q_4, var)) => (q_4, var),
        None => (Scalar::zero(), composer.zero_var),
    };

    let (q_l, a) = q_l_a;
    let (q_r, b) = q_r_b;

    let q_o = -Scalar::one();

    // Compute the output wire
    let a_eval = composer.variables[&a];
    let b_eval = composer.variables[&b];
    let d_eval = composer.variables[&d];
    let c_eval = (q_l * a_eval) + (q_r * b_eval) + (q_4 * d_eval) + q_c + pi;
    let c = composer.add_input(c_eval);

    big_add_gate(composer, a, b, c, Some(d), q_l, q_r, q_o, q_4, q_c, pi)
}

/// Adds a simple and basic addition to the circuit between to `Variable`s
/// returning the resulting `Variable`.
pub fn mul(
    composer: &mut StandardComposer,
    q_m: Scalar,
    a: Variable,
    b: Variable,
    q_c: Scalar,
    pi: Scalar,
) -> Variable {
    big_mul(composer, q_m, a, b, None, q_c, pi)
}

/// Adds a width-4 `big_mul_gate` with the left, right and fourth inputs
/// and it's scaling factors, computing & returning the output (result)
/// `Variable` and adding the corresponding mul constraint.
///
/// This type of gate is usually used when we don't need to have
/// the largest amount of performance and the minimum circuit-size
/// possible. Since it defaults some of the selector coeffs = 0 in order
/// to reduce the verbosity and complexity.
///
/// Forces `q_l * (w_l + w_r) + w_4 * q_4 + q_c + PI = w_o(computed by the gate)`.
/// XXX: This API is not consistent. It should use tuples and not individual fields
pub fn big_mul(
    composer: &mut StandardComposer,
    q_m: Scalar,
    a: Variable,
    b: Variable,
    q_4_d: Option<(Scalar, Variable)>,
    q_c: Scalar,
    pi: Scalar,
) -> Variable {
    let q_o = -Scalar::one();

    // Check if advice wire is available
    let (q_4, d) = match q_4_d {
        Some((q_4, var)) => (q_4, var),
        None => (Scalar::zero(), composer.zero_var),
    };

    // Compute output wire
    let a_eval = composer.variables[&a];
    let b_eval = composer.variables[&b];
    let d_eval = composer.variables[&d];
    let c_eval = (q_m * a_eval * b_eval) + (q_4 * d_eval) + q_c + pi;
    let c = composer.add_input(c_eval);

    big_mul_gate(composer, a, b, c, Some(d), q_m, q_o, q_c, q_4, pi)
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use super::*;
    use dusk_bls12_381::Scalar;

    #[test]
    fn test_public_inputs() {
        let res = gadget_tester(
            |composer| {
                let var_one = composer.add_input(Scalar::one());

                let should_be_three = big_add(
                    composer,
                    var_one.into(),
                    var_one.into(),
                    None,
                    Scalar::zero(),
                    Scalar::one(),
                );
                composer.constrain_to_constant(should_be_three, Scalar::from(3), Scalar::zero());
                let should_be_four = big_add(
                    composer,
                    var_one.into(),
                    var_one.into(),
                    None,
                    Scalar::zero(),
                    Scalar::from(2),
                );
                composer.constrain_to_constant(should_be_four, Scalar::from(4), Scalar::zero());
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_correct_add_mul_gate() {
        let res = gadget_tester(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) = 280
                let four = composer.add_input(Scalar::from(4));
                let five = composer.add_input(Scalar::from(5));
                let six = composer.add_input(Scalar::from(6));
                let seven = composer.add_input(Scalar::from(7));

                let fourteen = big_add(
                    composer,
                    four.into(),
                    five.into(),
                    Some(five.into()),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let twenty = big_add(
                    composer,
                    six.into(),
                    seven.into(),
                    Some(seven.into()),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                // There are quite a few ways to check the equation is correct, depending on your circumstance
                // If we already have the output wire, we can constrain the output of the mul_gate to be equal to it
                // If we do not, we can compute it using the `mul`
                // If the output is public, we can also constrain the output wire of the mul gate to it. This is what this test does
                let output = mul(
                    composer,
                    Scalar::one(),
                    fourteen,
                    twenty,
                    Scalar::zero(),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(output, Scalar::from(280), Scalar::zero());
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_correct_add_gate() {
        let res = gadget_tester(
            |composer| {
                let zero = composer.add_input(Scalar::zero());
                let one = composer.add_input(Scalar::one());

                let c = add(
                    composer,
                    (Scalar::one(), one),
                    (Scalar::zero(), zero),
                    Scalar::from(2u64),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(c, Scalar::from(3), Scalar::zero());
            },
            32,
        );
        assert!(res.is_ok())
    }

    #[test]
    fn test_correct_big_add_mul_gate() {
        let res = gadget_tester(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) + (8*9) = 352
                let four = composer.add_input(Scalar::from(4));
                let five = composer.add_input(Scalar::from(5));
                let six = composer.add_input(Scalar::from(6));
                let seven = composer.add_input(Scalar::from(7));
                let nine = composer.add_input(Scalar::from(9));

                let fourteen = big_add(
                    composer,
                    four.into(),
                    five.into(),
                    Some(five.into()),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let twenty = big_add(
                    composer,
                    six.into(),
                    seven.into(),
                    Some(seven.into()),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let output = big_mul(
                    composer,
                    Scalar::one(),
                    fourteen,
                    twenty,
                    Some((Scalar::from(8), nine)),
                    Scalar::zero(),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(output, Scalar::from(352), Scalar::zero());
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_incorrect_add_mul_gate() {
        let res = gadget_tester(
            |composer| {
                // Verify that (5+5) * (6+7) != 117
                let five = composer.add_input(Scalar::from(5));
                let six = composer.add_input(Scalar::from(6));
                let seven = composer.add_input(Scalar::from(7));

                let five_plus_five = big_add(
                    composer,
                    five.into(),
                    five.into(),
                    None,
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let six_plus_seven = big_add(
                    composer,
                    six.into(),
                    seven.into(),
                    None,
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let output = mul(
                    composer,
                    Scalar::one(),
                    five_plus_five,
                    six_plus_seven,
                    Scalar::zero(),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(output, Scalar::from(117), Scalar::zero());
            },
            200,
        );
        assert!(res.is_err());
    }
}
