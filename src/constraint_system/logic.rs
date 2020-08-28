// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

use crate::bit_iterator::*;
use crate::constraint_system::StandardComposer;
use crate::constraint_system::{Variable, WireData};
use dusk_bls12_381::Scalar;

impl StandardComposer {
    // Performs a logical AND or XOR op between the inputs provided for the specified
    /// number of bits.
    ///
    /// Each logic gate adds `(num_bits / 2) + 1` gates to the circuit to perform the
    /// whole operation.
    ///
    /// ## Selector
    /// - is_xor_gate = 1 -> Performs XOR between the first `num_bits` for `a` and `b`.
    /// - is_xor_gate = 0 -> Performs AND between the first `num_bits` for `a` and `b`.
    ///
    /// ## Panics
    /// This function will panic if the num_bits specified is not even `num_bits % 2 != 0`.
    fn logic_gate(
        &mut self,
        a: Variable,
        b: Variable,
        num_bits: usize,
        is_xor_gate: bool,
    ) -> Variable {
        // Since we work on base4, we need to guarantee that we have an even
        // number of bits representing the greatest input.
        assert_eq!(num_bits & 1, 0);
        // We will have exactly `num_bits / 2` quads (quaternary digits) representing
        // both numbers.
        let num_quads = num_bits >> 1;
        // Allocate accumulators for gate construction.
        let mut left_accumulator = Scalar::zero();
        let mut right_accumulator = Scalar::zero();
        let mut out_accumulator = Scalar::zero();
        let mut left_quad: u8;
        let mut right_quad: u8;
        // Get vars as bits and reverse them to get the Little Endian repr.
        let a_bit_iter = BitIterator8::new(self.variables[&a].to_bytes());
        let a_bits: Vec<_> = a_bit_iter.skip(256 - num_bits).collect();
        let b_bit_iter = BitIterator8::new(self.variables[&b].to_bytes());
        let b_bits: Vec<_> = b_bit_iter.skip(256 - num_bits).collect();
        // XXX Doc this
        assert!(a_bits.len() >= num_bits);
        assert!(b_bits.len() >= num_bits);

        // If we take a look to the program memory structure of the ref. impl.
        // * +-----+-----+-----+-----+
        // * |  A  |  B  |  C  |  D  |
        // * +-----+-----+-----+-----+
        // * | 0   | 0   | w1  | 0   |
        // * | a1  | b1  | w2  | c1  |
        // * | a2  | b2  | w3  | c2  |
        // * |  :  |  :  |  :  |  :  |
        // * | an  | bn  | --- | cn  |
        // * +-----+-----+-----+-----+
        // We need to have w_4, w_l and w_r pointing to one gate ahead of w_o.
        // We increase the gate idx and assign w_4, w_l and w_r to `zero`.
        // Now we can add the first row as: `| 0 | 0 | -- | 0 |`.
        // Note that `w_1` will be set on the first loop iteration.
        self.perm
            .add_variable_to_map(self.zero_var, WireData::Left(self.n));
        self.perm
            .add_variable_to_map(self.zero_var, WireData::Right(self.n));
        self.perm
            .add_variable_to_map(self.zero_var, WireData::Fourth(self.n));
        self.w_l.push(self.zero_var);
        self.w_r.push(self.zero_var);
        self.w_4.push(self.zero_var);
        // Increase the gate index so we can add the following rows in the correct order.
        self.n += 1;

        // Start generating accumulator rows and adding them to the circuit.
        // Note that we will do this process exactly `num_bits / 2` counting that
        // the first step above was done correctly to obtain the right format the the first row.
        // This means that we will need to pad the end of the memory program once we've built it.
        // As we can see in the last row structure: `| an  | bn  | --- | cn  |`.
        for i in 0..num_quads {
            // On each round, we will commit every accumulator step. To do so,
            // we first need to get the ith quads of `a` and `b` and then compute
            // `out_quad`(logical OP result) and `prod_quad`(intermediate prod result).

            // Here we compute each quad by taking the most significant bit
            // multiplying it by two and adding to it the less significant
            // bit to form the quad with a ternary value encapsulated in an `u8`
            // in Big Endian form.
            left_quad = {
                let idx = i << 1;
                ((a_bits[idx] as u8) << 1) + (a_bits[idx + 1] as u8)
            };
            right_quad = {
                let idx = i << 1;
                ((b_bits[idx] as u8) << 1) + (b_bits[idx + 1] as u8)
            };
            let left_quad_fr = Scalar::from(left_quad as u64);
            let right_quad_fr = Scalar::from(right_quad as u64);
            // The `out_quad` is the result of the bitwise ops `&` or `^` between
            // the left and right quads. The op is decided with a boolean flag set
            // as input of the function.
            let out_quad_fr = match is_xor_gate {
                true => Scalar::from((left_quad ^ right_quad) as u64),
                false => Scalar::from((left_quad & right_quad) as u64),
            };
            // We also need to allocate a helper item which is the result
            // of the product between the left and right quads.
            // This param is identified as `w` in the program memory and
            // is needed to prevent the degree of our quotient polynomial from blowing up
            let prod_quad_fr = Scalar::from((left_quad * right_quad) as u64);

            // Now that we've computed this round results, we need to apply the
            // logic transition constraint that will check the following:
            // a      - 4 . a  ϵ [0, 1, 2, 3]
            //   i + 1        i
            //
            //
            //
            //
            //  b      - 4 . b  ϵ [0, 1, 2, 3]
            //   i + 1        i
            //
            //
            //
            //
            //                    /                 \          /                 \
            //  c      - 4 . c  = | a      - 4 . a  | (& OR ^) | b      - 4 . b  |
            //   i + 1        i   \  i + 1        i /          \  i + 1        i /
            //
            let prev_left_accum = left_accumulator;
            let prev_right_accum = right_accumulator;
            let prev_out_accum = out_accumulator;
            // We also need to add the computed quad fr_s to the circuit representing a logic gate.
            // To do so, we just mul by 4 the previous accomulated result and we add to it
            // the new computed quad.
            // With this technique we're basically accumulating the quads and adding them to get back to the
            // starting value, at the i-th iteration.
            //          i
            //         ===
            //         \                     j
            //  x   =  /    q            . 4
            //   i     ===   (bits/2 - j)
            //        j = 0
            //
            left_accumulator *= Scalar::from(4u64);
            left_accumulator += left_quad_fr;
            right_accumulator *= Scalar::from(4u64);
            right_accumulator += right_quad_fr;
            out_accumulator *= Scalar::from(4u64);
            out_accumulator += out_quad_fr;
            // Apply logic transition constraints.
            assert!(left_accumulator - (prev_left_accum * Scalar::from(4u64)) < Scalar::from(4u64));
            assert!(
                right_accumulator - (prev_right_accum * Scalar::from(4u64)) < Scalar::from(4u64)
            );
            assert!(out_accumulator - (prev_out_accum * Scalar::from(4u64)) < Scalar::from(4u64));

            // Get variables pointing to the previous accumulated values.
            let var_a = self.add_input(left_accumulator);
            let var_b = self.add_input(right_accumulator);
            // On the last row of the program memory, we need to pad the
            // output wire with a zero since we started to include it's
            // accumulators one gate before the other wire ones.
            let var_c = match i == num_quads {
                true => self.zero_var,
                false => self.add_input(prod_quad_fr),
            };
            let var_4 = self.add_input(out_accumulator);
            // Add the variables to the variable map linking them to it's
            // corresponding gate index.
            //
            // Note that by doing this, we are basically setting the wire_coeffs
            // of the wire polynomials, but we still need to link the selector_poly
            // coefficients in order to be able to have complete gates.
            //
            // Also note that here we're setting left, right and fourth variables to the
            // actual gate, meanwhile we set out to the previous gate.
            self.perm.add_variable_to_map(var_a, WireData::Left(self.n));
            self.perm
                .add_variable_to_map(var_b, WireData::Right(self.n));
            self.perm
                .add_variable_to_map(var_4, WireData::Fourth(self.n));
            self.perm
                .add_variable_to_map(var_c, WireData::Output(self.n - 1));
            // Push the variables to it's actual wire vector storage
            self.w_l.push(var_a);
            self.w_r.push(var_b);
            self.w_o.push(var_c);
            self.w_4.push(var_4);
            // Update the gate index
            self.n += 1;
        }

        // We have one missing value for the last row of the program memory which
        // is `w_o` since the rest of wires are pointing one gate ahead.
        // To fix this, we simply pad with a 0 so the last row of the program memory
        // will look like this:
        // | an  | bn  | --- | cn  |
        self.perm
            .add_variable_to_map(self.zero_var, WireData::Output(self.n - 1));
        self.w_o.push(self.zero_var);

        // Now the wire values are set for each gate, indexed and mapped in the
        // `variable_map` inside of the `Permutation` struct.
        // Now we just need to extend the selector polynomials with the appropriate
        // coefficients to form complete logic gates.
        for _ in 0..num_quads {
            self.q_m.push(Scalar::zero());
            self.q_l.push(Scalar::zero());
            self.q_r.push(Scalar::zero());
            self.q_arith.push(Scalar::zero());
            self.q_o.push(Scalar::zero());
            self.q_4.push(Scalar::zero());
            self.q_range.push(Scalar::zero());
            self.q_fixed_group_add.push(Scalar::zero());
            self.q_variable_group_add.push(Scalar::zero());
            match is_xor_gate {
                true => {
                    self.q_c.push(-Scalar::one());
                    self.q_logic.push(-Scalar::one());
                }
                false => {
                    self.q_c.push(Scalar::one());
                    self.q_logic.push(Scalar::one());
                }
            };
        }
        // For the last gate, `q_c` and `q_logic` we use no-op values (Zero).
        self.q_m.push(Scalar::zero());
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        self.q_arith.push(Scalar::zero());
        self.q_o.push(Scalar::zero());
        self.q_4.push(Scalar::zero());
        self.q_range.push(Scalar::zero());
        self.q_fixed_group_add.push(Scalar::zero());
        self.q_variable_group_add.push(Scalar::zero());

        self.q_c.push(Scalar::zero());
        self.q_logic.push(Scalar::zero());

        // We also need to extend the `public_inputs` Vec with
        // zeros since the coeffs will not be added by the user as
        // they are not needed.
        //
        // It makes no sense to allow the user introduce any kind of value
        // in the middle of the logical gate iteration.
        let zeros = vec![Scalar::zero(); num_quads + 1];
        self.public_inputs.extend(zeros.iter());

        // Now we need to assert that the sum of accumulated values
        // matches the original values provided to the fn.
        // Note that we're only considering the quads that are included
        // in the range 0..num_bits. So, when actually executed, we're checking that
        // x & ((1 << num_bits +1) -1) == [0..num_quads] accumulated sums of x.
        //
        // We could also check that the last gates wire coefficients match the
        // original values introduced in the function taking into account the bitnum
        // specified on the fn call parameters.
        // This can be done with an `assert_equal` constraint gate or simply
        // by taking the values behind the n'th variables of `w_l` & `w_r` and
        // checking that they're equal to the original ones behind the variables
        // sent through the function parameters.
        assert_eq!(
            self.variables[&a]
                & (Scalar::from(2u64).pow(&[(num_bits) as u64, 0, 0, 0]) - Scalar::one()),
            self.variables[&self.w_l[self.n - 1]]
        );
        assert_eq!(
            self.variables[&b]
                & (Scalar::from(2u64).pow(&[(num_bits) as u64, 0, 0, 0]) - Scalar::one()),
            self.variables[&self.w_r[self.n - 1]]
        );

        // Once the inputs are checked against the accumulated additions,
        // we can safely return the resulting variable of the gate computation
        // which is stored on the last program memory row and in the column that
        // `w_4` is holding.
        self.w_4[self.w_4.len() - 1]
    }

    /// Adds a logical XOR gate that performs the XOR between two values for the
    /// specified first `num_bits` returning a `Variable` holding the result.
    ///
    /// # Panics
    ///
    /// If the `num_bits` specified in the fn params is odd.
    pub fn xor_gate(&mut self, a: Variable, b: Variable, num_bits: usize) -> Variable {
        self.logic_gate(a, b, num_bits, true)
    }

    /// Adds a logical AND gate that performs the bitwise AND between two values
    /// for the specified first `num_bits` returning a `Variable` holding the result.
    ///
    /// # Panics
    ///
    /// If the `num_bits` specified in the fn params is odd.
    pub fn and_gate(&mut self, a: Variable, b: Variable, num_bits: usize) -> Variable {
        self.logic_gate(a, b, num_bits, false)
    }
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use dusk_bls12_381::Scalar;

    #[test]
    fn test_logic_xor_and_constraint() {
        // Should pass since the XOR result is correct and the bit-num is even.
        let res = gadget_tester(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(500u64));
                let witness_b = composer.add_input(Scalar::from(357u64));
                let xor_res = composer.xor_gate(witness_a, witness_b, 10);
                // Check that the XOR result is indeed what we are expecting.
                composer.constrain_to_constant(
                    xor_res,
                    Scalar::from(500u64 ^ 357u64),
                    Scalar::zero(),
                );
            },
            200,
        );
        assert!(res.is_ok());

        // Should pass since the AND result is correct even the bit-num is even.
        let res = gadget_tester(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(469u64));
                let witness_b = composer.add_input(Scalar::from(321u64));
                let xor_res = composer.and_gate(witness_a, witness_b, 10);
                // Check that the AND result is indeed what we are expecting.
                composer.constrain_to_constant(
                    xor_res,
                    Scalar::from(469u64 & 321u64),
                    Scalar::zero(),
                );
            },
            200,
        );
        assert!(res.is_ok());

        // Should not pass since the XOR result is not correct even the bit-num is even.
        let res = gadget_tester(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(139u64));
                let witness_b = composer.add_input(Scalar::from(33u64));
                let xor_res = composer.xor_gate(witness_a, witness_b, 10);
                // Check that the XOR result is indeed what we are expecting.
                composer.constrain_to_constant(
                    xor_res,
                    Scalar::from(139u64 & 33u64),
                    Scalar::zero(),
                );
            },
            200,
        );
        assert!(res.is_err());

        // Should pass even the bitnum is less than the number bit-size
        let res = gadget_tester(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(256u64));
                let witness_b = composer.add_input(Scalar::from(235u64));
                let xor_res = composer.xor_gate(witness_a, witness_b, 2);
                // Check that the XOR result is indeed what we are expecting.
                composer.constrain_to_constant(xor_res, Scalar::from(256 ^ 235), Scalar::zero());
            },
            200,
        );
        assert!(res.is_err());
    }

    #[test]
    #[should_panic]
    fn test_logical_gate_odd_bit_num() {
        // Should fail since the bit-num is odd.
        let _ = gadget_tester(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(500u64));
                let witness_b = composer.add_input(Scalar::from(499u64));
                let xor_res = composer.xor_gate(witness_a, witness_b, 9);
                // Check that the XOR result is indeed what we are expecting.
                composer.constrain_to_constant(xor_res, Scalar::from(7u64), Scalar::zero());
            },
            200,
        );
    }
}
