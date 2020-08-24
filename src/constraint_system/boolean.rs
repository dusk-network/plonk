use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use dusk_bls12_381::Scalar;

impl StandardComposer {
    /// Adds a boolean constraint (also known as binary constraint) where
    /// the gate eq. will enforce that the `Variable` received is either `0`
    /// or `1` by adding a constraint in the circuit.
    ///
    /// Note that using this constraint with whatever `Variable` that is not
    /// representing a value equalling 0 or 1, will always force the equation to fail.
    pub fn boolean_gate(&mut self, a: Variable) -> Variable {
        self.w_l.push(a);
        self.w_r.push(a);
        self.w_o.push(a);
        self.w_4.push(self.zero_var);

        self.q_m.push(Scalar::one());
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        self.q_o.push(-Scalar::one());
        self.q_c.push(Scalar::zero());
        self.q_4.push(Scalar::zero());
        self.q_arith.push(Scalar::one());

        self.q_range.push(Scalar::zero());
        self.q_logic.push(Scalar::zero());
        self.q_ecc.push(Scalar::zero());

        self.public_inputs.push(Scalar::zero());

        self.perm
            .add_variables_to_map(a, a, a, self.zero_var, self.n);

        self.n += 1;

        a
    }
}
#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use dusk_bls12_381::Scalar;
    #[test]
    fn test_correct_bool_gate() {
        let res = gadget_tester(
            |composer| {
                let zero = composer.add_input(Scalar::zero());
                let one = composer.add_input(Scalar::one());

                composer.boolean_gate(zero);
                composer.boolean_gate(one);
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

                composer.boolean_gate(zero);
                composer.boolean_gate(one);
            },
            32,
        );
        assert!(res.is_err())
    }
}
