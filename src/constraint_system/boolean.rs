use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use dusk_bls12_381::Scalar;

/// Adds a boolean constraint (also known as binary constraint) where
/// the gate eq. will enforce that the `Variable` received is either `0`
/// or `1` by adding a constraint in the circuit.
///
/// Note that using this constraint with whatever `Variable` that is not
/// representing a value equalling 0 or 1, will always force the equation to fail.
pub fn gate(composer: &mut StandardComposer, a: Variable) -> Variable {
    composer.w_l.push(a);
    composer.w_r.push(a);
    composer.w_o.push(a);
    composer.w_4.push(composer.zero_var);

    composer.q_m.push(Scalar::one());
    composer.q_l.push(Scalar::zero());
    composer.q_r.push(Scalar::zero());
    composer.q_o.push(-Scalar::one());
    composer.q_c.push(Scalar::zero());
    composer.q_4.push(Scalar::zero());
    composer.q_arith.push(Scalar::one());

    composer.q_range.push(Scalar::zero());
    composer.q_logic.push(Scalar::zero());

    composer.public_inputs.push(Scalar::zero());

    composer
        .perm
        .add_variables_to_map(a, a, a, composer.zero_var, composer.n);

    composer.n += 1;

    a
}
#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use super::*;
    use dusk_bls12_381::Scalar;
    #[test]
    fn test_correct_bool_gate() {
        let res = gadget_tester(
            |composer| {
                let zero = composer.add_input(Scalar::zero());
                let one = composer.add_input(Scalar::one());

                gate(composer, zero);
                gate(composer, one);
            },
            32,
        );
        assert!(res.is_ok())
    }

    #[test]
    fn test_incorrect_bool_gate() {
        let res = gadget_tester(
            |composer| {
                let zero = composer.add_input(Scalar::from(5));
                let one = composer.add_input(Scalar::one());

                gate(composer, zero);
                gate(composer, one);
            },
            32,
        );
        assert!(res.is_err())
    }
}
