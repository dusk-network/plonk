// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use dusk_bls12_381::BlsScalar;

impl StandardComposer {
    /// Adds a width-3 add gate to the circuit, linking the addition of the
    /// provided inputs, scaled by the selector coefficients with the output
    /// provided.
    pub fn add_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_o: BlsScalar,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Variable {
        self.big_add_gate(
            a,
            b,
            c,
            None,
            q_l,
            q_r,
            q_o,
            BlsScalar::zero(),
            q_c,
            pi,
        )
    }

    /// Adds a width-4 add gate to the plookup circuit and it's corresponding
    /// constraint.
    pub fn big_add_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        d: Option<Variable>,
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_o: BlsScalar,
        q_4: BlsScalar,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Variable {
        // Check if advice wire has a value
        let d = match d {
            Some(var) => var,
            None => self.zero_var,
        };

        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);
        self.w_4.push(d);

        // For an add gate, q_m is zero
        self.q_m.push(BlsScalar::zero());

        // Add selector vectors
        self.q_l.push(q_l);
        self.q_r.push(q_r);
        self.q_o.push(q_o);
        self.q_c.push(q_c);
        self.q_4.push(q_4);
        self.q_arith.push(BlsScalar::one());
        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());
        self.q_lookup.push(BlsScalar::zero());

        if let Some(pi) = pi {
            assert!(self.public_inputs_sparse_store.insert(self.n, pi).is_none(),"The invariant of already having a PI inserted for this position should never exist");
        }

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }
    /// Adds a width-3 mul gate to the circuit linking the product of the
    /// provided inputs scaled by the selector coefficient `q_m` with the output
    /// provided scaled by `q_o`.
    ///
    /// Note that this gate requires to provide the actual result of the gate
    /// (output wire) since it will just add a `mul constraint` to the circuit.
    pub fn mul_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_m: BlsScalar,
        q_o: BlsScalar,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Variable {
        self.big_mul_gate(a, b, c, None, q_m, q_o, q_c, BlsScalar::zero(), pi)
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
    /// Forces `q_m * (w_l * w_r) + w_4 * q_4 + q_c + PI = q_o * w_o`.
    ///
    /// `{w_l, w_r, w_o, w_4} = {a, b, c, d}`
    // XXX: Maybe make these tuples instead of individual field?
    pub fn big_mul_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        d: Option<Variable>,
        q_m: BlsScalar,
        q_o: BlsScalar,
        q_c: BlsScalar,
        q_4: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Variable {
        // Check if advice wire has a value
        let d = match d {
            Some(var) => var,
            None => self.zero_var,
        };

        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);
        self.w_4.push(d);

        // For a mul gate q_L and q_R is zero
        self.q_l.push(BlsScalar::zero());
        self.q_r.push(BlsScalar::zero());

        // Add selector vectors
        self.q_m.push(q_m);
        self.q_o.push(q_o);
        self.q_c.push(q_c);
        self.q_4.push(q_4);
        self.q_arith.push(BlsScalar::one());

        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());
        self.q_lookup.push(BlsScalar::zero());

        if let Some(pi) = pi {
            assert!(
                self.public_inputs_sparse_store.insert(self.n, pi).is_none(),"The invariant of already having a PI inserted for this position should never exist"
            );
        }

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }

    /// Adds a [`StandardComposer::big_add_gate`] with the left and right
    /// inputs and it's scaling factors, computing & returning the output
    /// (result) [`Variable`], and adding the corresponding addition
    /// constraint.
    ///
    /// This type of gate is usually used when we don't need to have
    /// the largest amount of performance as well as the minimum circuit-size
    /// possible. Since it defaults some of the selector coeffs = 0 in order
    /// to reduce the verbosity and complexity.
    ///
    /// Forces `q_l * w_l + q_r * w_r + q_c + PI = w_o(computed by the gate)`.
    pub fn add(
        &mut self,
        q_l_a: (BlsScalar, Variable),
        q_r_b: (BlsScalar, Variable),
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Variable {
        self.big_add(q_l_a, q_r_b, None, q_c, pi)
    }

    /// Adds a [`StandardComposer::big_add_gate`] with the left, right and
    /// fourth inputs and it's scaling factors, computing & returning the
    /// output (result) [`Variable`] and adding the corresponding addition
    /// constraint.
    ///
    /// This type of gate is usually used when we don't need to have
    /// the largest amount of performance and the minimum circuit-size
    /// possible. Since it defaults some of the selector coeffs = 0 in order
    /// to reduce the verbosity and complexity.
    ///
    /// Forces `q_l * w_l + q_r * w_r + q_4 * w_4 + q_c + PI = w_o(computed by
    /// the gate)`.
    pub fn big_add(
        &mut self,
        q_l_a: (BlsScalar, Variable),
        q_r_b: (BlsScalar, Variable),
        q_4_d: Option<(BlsScalar, Variable)>,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Variable {
        // Check if advice wire is available
        let (q_4, d) = match q_4_d {
            Some((q_4, var)) => (q_4, var),
            None => (BlsScalar::zero(), self.zero_var),
        };

        let (q_l, a) = q_l_a;
        let (q_r, b) = q_r_b;

        let q_o = -BlsScalar::one();

        // Compute the output wire
        let a_eval = self.variables[&a];
        let b_eval = self.variables[&b];
        let d_eval = self.variables[&d];
        let c_eval = (q_l * a_eval)
            + (q_r * b_eval)
            + (q_4 * d_eval)
            + q_c
            + pi.unwrap_or_default();
        let c = self.add_input(c_eval);

        self.big_add_gate(a, b, c, Some(d), q_l, q_r, q_o, q_4, q_c, pi)
    }

    /// Adds a [`StandardComposer::big_mul_gate`] with the left, right
    /// and fourth inputs and it's scaling factors, computing & returning
    /// the output (result) [`Variable`] and adding the corresponding mul
    /// constraint.
    ///
    /// This type of gate is usually used when we don't need to have
    /// the largest amount of performance and the minimum circuit-size
    /// possible. Since it defaults some of the selector coeffs = 0 in order
    /// to reduce the verbosity and complexity.
    ///
    /// Forces `q_m * (w_l * w_r) + w_4 * q_4 + q_c + PI = w_o(computed by the
    /// gate)`.
    ///
    /// `{w_l, w_r, w_4} = {a, b, d}`
    pub fn mul(
        &mut self,
        q_m: BlsScalar,
        a: Variable,
        b: Variable,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Variable {
        self.big_mul(q_m, a, b, None, q_c, pi)
    }

    /// Adds a width-4 [`StandardComposer::big_mul_gate`] with the left, right
    /// and fourth inputs and it's scaling factors, computing & returning
    /// the output (result) [`Variable`] and adding the corresponding mul
    /// constraint.
    ///
    /// This type of gate is usually used when we don't need to have
    /// the largest amount of performance and the minimum circuit-size
    /// possible. Since it defaults some of the selector coeffs = 0 in order
    /// to reduce the verbosity and complexity.
    ///
    /// Forces `q_m * (w_l * w_r) + w_4 * q_4 + q_c + PI = w_o(computed by the
    /// gate)`.
    ///
    /// `{w_l, w_r, w_4} = {a, b, d}`
    pub fn big_mul(
        &mut self,
        q_m: BlsScalar,
        a: Variable,
        b: Variable,
        q_4_d: Option<(BlsScalar, Variable)>,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) -> Variable {
        let q_o = -BlsScalar::one();

        // Check if advice wire is available
        let (q_4, d) = match q_4_d {
            Some((q_4, var)) => (q_4, var),
            None => (BlsScalar::zero(), self.zero_var),
        };

        // Compute output wire
        let a_eval = self.variables[&a];
        let b_eval = self.variables[&b];
        let d_eval = self.variables[&d];
        let c_eval = (q_m * a_eval * b_eval)
            + (q_4 * d_eval)
            + q_c
            + pi.unwrap_or_default();
        let c = self.add_input(c_eval);

        self.big_mul_gate(a, b, c, Some(d), q_m, q_o, q_c, q_4, pi)
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::constraint_system::helper::*;
    use dusk_bls12_381::BlsScalar;

    #[test]
    fn test_public_inputs() {
        let res = gadget_tester(
            |composer| {
                let var_one = composer.add_input(BlsScalar::one());

                let should_be_three = composer.big_add(
                    (BlsScalar::one(), var_one),
                    (BlsScalar::one(), var_one),
                    None,
                    BlsScalar::zero(),
                    Some(BlsScalar::one()),
                );
                composer.constrain_to_constant(
                    should_be_three,
                    BlsScalar::from(3),
                    None,
                );
                let should_be_four = composer.big_add(
                    (BlsScalar::one(), var_one),
                    (BlsScalar::one(), var_one),
                    None,
                    BlsScalar::zero(),
                    Some(BlsScalar::from(2)),
                );
                composer.constrain_to_constant(
                    should_be_four,
                    BlsScalar::from(4),
                    None,
                );
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
                let four = composer.add_input(BlsScalar::from(4));
                let five = composer.add_input(BlsScalar::from(5));
                let six = composer.add_input(BlsScalar::from(6));
                let seven = composer.add_input(BlsScalar::from(7));

                let fourteen = composer.big_add(
                    (BlsScalar::one(), four),
                    (BlsScalar::one(), five),
                    Some((BlsScalar::one(), five)),
                    BlsScalar::zero(),
                    None,
                );

                let twenty = composer.big_add(
                    (BlsScalar::one(), six),
                    (BlsScalar::one(), seven),
                    Some((BlsScalar::one(), seven)),
                    BlsScalar::zero(),
                    None,
                );

                // There are quite a few ways to check the equation is correct,
                // depending on your circumstance If we already
                // have the output wire, we can constrain the output of the
                // mul_gate to be equal to it If we do not, we
                // can compute it using the `mul` If the output
                // is public, we can also constrain the output wire of the mul
                // gate to it. This is what this test does
                let output = composer.mul(
                    BlsScalar::one(),
                    fourteen,
                    twenty,
                    BlsScalar::zero(),
                    None,
                );
                composer.constrain_to_constant(
                    output,
                    BlsScalar::from(280),
                    None,
                );
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_correct_add_gate() {
        let res = gadget_tester(
            |composer| {
                let zero = composer.zero_var();
                let one = composer.add_input(BlsScalar::one());

                let c = composer.add(
                    (BlsScalar::one(), one),
                    (BlsScalar::zero(), zero),
                    BlsScalar::from(2u64),
                    None,
                );
                composer.constrain_to_constant(c, BlsScalar::from(3), None);
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
                let four = composer.add_input(BlsScalar::from(4));
                let five = composer.add_input(BlsScalar::from(5));
                let six = composer.add_input(BlsScalar::from(6));
                let seven = composer.add_input(BlsScalar::from(7));
                let nine = composer.add_input(BlsScalar::from(9));

                let fourteen = composer.big_add(
                    (BlsScalar::one(), four),
                    (BlsScalar::one(), five),
                    Some((BlsScalar::one(), five)),
                    BlsScalar::zero(),
                    None,
                );

                let twenty = composer.big_add(
                    (BlsScalar::one(), six),
                    (BlsScalar::one(), seven),
                    Some((BlsScalar::one(), seven)),
                    BlsScalar::zero(),
                    None,
                );

                let output = composer.big_mul(
                    BlsScalar::one(),
                    fourteen,
                    twenty,
                    Some((BlsScalar::from(8), nine)),
                    BlsScalar::zero(),
                    None,
                );
                composer.constrain_to_constant(
                    output,
                    BlsScalar::from(352),
                    None,
                );
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
                let five = composer.add_input(BlsScalar::from(5));
                let six = composer.add_input(BlsScalar::from(6));
                let seven = composer.add_input(BlsScalar::from(7));

                let five_plus_five = composer.big_add(
                    (BlsScalar::one(), five),
                    (BlsScalar::one(), five),
                    None,
                    BlsScalar::zero(),
                    None,
                );

                let six_plus_seven = composer.big_add(
                    (BlsScalar::one(), six),
                    (BlsScalar::one(), seven),
                    None,
                    BlsScalar::zero(),
                    None,
                );

                let output = composer.mul(
                    BlsScalar::one(),
                    five_plus_five,
                    six_plus_seven,
                    BlsScalar::zero(),
                    None,
                );
                composer.constrain_to_constant(
                    output,
                    BlsScalar::from(117),
                    None,
                );
            },
            200,
        );
        assert!(res.is_err());
    }
}
