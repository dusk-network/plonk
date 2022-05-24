// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::bit_iterator::*;
use crate::constraint_system::TurboComposer;
use crate::constraint_system::{WireData, Witness};
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;

impl TurboComposer {
    /// Performs a logical AND or XOR op between the inputs provided for the
    /// specified number of bits (counting from the least significant bit).
    ///
    /// Each logic gate adds `(num_bits / 2) + 1` gates to the circuit to
    /// perform the whole operation.
    ///
    /// ## Constraint
    /// - is_component_xor = 1 -> Performs XOR between the first `num_bits` for
    ///   `a` and `b`.
    /// - is_component_xor = 0 -> Performs AND between the first `num_bits` for
    ///   `a` and `b`.
    ///
    /// # Panics
    /// This function will panic if the num_bits specified is not even, ie.
    /// `num_bits % 2 != 0`.
    fn logic_gate(
        &mut self,
        a: Witness,
        b: Witness,
        num_bits: usize,
        is_component_xor: bool,
    ) -> Witness {
        // We will need to split the input into `num_bits / 2` two-bit chunks.
        // This is why we can only accept an even number of `num_bits`.
        assert_eq!(num_bits & 1, 0);
        // If `num_bits` is greater than 256 (which is the amount of bits in a
        // `BlsScalar`), set `num_bits` to 256
        let num_bits = {
            match num_bits < 256 {
                true => num_bits,
                false => 256,
            }
        };

        // We will have exactly `num_bits / 2` quads (quaternary digits)
        // representing both numbers.
        let num_quads = num_bits >> 1;

        // Allocate the bls accumulators for gate construction.
        let mut left_acc = BlsScalar::zero();
        let mut right_acc = BlsScalar::zero();
        let mut out_acc = BlsScalar::zero();
        let mut left_quad: u8;
        let mut right_quad: u8;

        // Get witnesses in bits in big endian and skip the first (256 -
        // num_bits) bits we are not interested in.
        let a_bit_iter = BitIterator8::new(self.witnesses[&a].to_bytes());
        let a_bits: Vec<_> = a_bit_iter.skip(256 - num_bits).collect();
        let b_bit_iter = BitIterator8::new(self.witnesses[&b].to_bytes());
        let b_bits: Vec<_> = b_bit_iter.skip(256 - num_bits).collect();

        assert!(a_bits.len() >= num_bits);
        assert!(b_bits.len() >= num_bits);

        // If we take a look to the program memory structure of the ref. impl.
        // * +-----+-----+-----+-----+
        // * |  A  |  B  |  C  |  D  |
        // * +-----+-----+-----+-----+
        // * | 0   | 0   | w1  | 0   |
        // * | a1  | b1  | w2  | d1  |
        // * | a2  | b2  | w3  | d2  |
        // * |  :  |  :  |  :  |  :  |
        // * | an  | bn  | 0   | dn  |
        // * +-----+-----+-----+-----+
        // The an, bn and dn are accumulators:
        //   an [& OR ^] bd = dn
        // At each step we shift the bits of the last result two positions to
        // the left and add the current quad.
        // The wn are product accumulators that are needed to prevent the
        // degree of the our quotient polynomial from blowing up.
        // We need to have d_i, a_i and b_i pointing to one gate ahead of c_i.
        // We increase the gate idx and assign d_i, a_i and b_i to `zero`.
        // Now we can add the first row as: `| 0 | 0 | -- | 0 |`.
        // Note that c_i will be set on the first loop iteration.
        self.perm
            .add_witness_to_map(Self::constant_zero(), WireData::Left(self.n));
        self.perm
            .add_witness_to_map(Self::constant_zero(), WireData::Right(self.n));
        self.perm.add_witness_to_map(
            Self::constant_zero(),
            WireData::Fourth(self.n),
        );
        self.a_w.push(Self::constant_zero());
        self.b_w.push(Self::constant_zero());
        self.d_w.push(Self::constant_zero());
        // Increase the gate index so we can add the following rows in the
        // correct order.
        self.n += 1;

        // Start generating accumulator rows and adding them to the circuit.
        // Note that we will do this process exactly `num_bits / 2` counting
        // that the first step above was done correctly to obtain the
        // right format the the first row. This means that we will need
        // to pad the end of the memory program once we've built it.
        // As we can see in the last row structure: `| an  | bn  | --- | dn  |`.
        for i in 0..num_quads {
            // On each round, we will commit every accumulator step. To do so,
            // we first need to get the ith quads of `a` and `b` and then
            // compute `out_quad`(logical OP result) and
            // `prod_quad`(intermediate prod result).

            // Here we compute each quad by taking the most significant bit
            // shifting it one position to the left and adding to it the less
            // significant bit to form the quad with a ternary value
            // encapsulated in an `u8` in Big Endian form.
            left_quad = {
                let idx = i * 2;
                ((a_bits[idx] as u8) << 1) + (a_bits[idx + 1] as u8)
            };
            right_quad = {
                let idx = i * 2;
                ((b_bits[idx] as u8) << 1) + (b_bits[idx + 1] as u8)
            };
            let left_quad_bls = BlsScalar::from(left_quad as u64);
            let right_quad_bls = BlsScalar::from(right_quad as u64);
            // The `out_quad` is the result of the bitwise ops `&` or `^`
            // between the left and right quads. The op is decided
            // with a boolean flag set as input of the function.
            let out_quad_bls = match is_component_xor {
                true => BlsScalar::from((left_quad ^ right_quad) as u64),
                false => BlsScalar::from((left_quad & right_quad) as u64),
            };
            // We also need to allocate a helper item which is the result
            // of the product between the left and right quads.
            // This param is identified as `w` in the program memory and
            // is needed to prevent the degree of our quotient polynomial from
            // blowing up
            let prod_quad_bls =
                BlsScalar::from((left_quad * right_quad) as u64);

            // Now that we've computed this round results, we need to apply the
            // logic transition constraint that will check that
            //   a_{i+1} - (a_i << 2) < 4
            //   b_{i+1} - (b_i << 2) < 4
            //   d_{i+1} - (d_i << 2) < 4   with d_i = a_i [& OR ^] b_i
            // Note that multiplying by four is the equivalent of shifting the
            // bits two positions to the left.
            let bls_four = BlsScalar::from(4u64);
            let prev_left_acc = left_acc;
            let prev_right_acc = right_acc;
            let prev_out_acc = out_acc;
            left_acc = left_acc * bls_four + left_quad_bls;
            right_acc = right_acc * bls_four + right_quad_bls;
            out_acc = out_acc * bls_four + out_quad_bls;
            // Apply logic transition gates.
            // a_{i+1} - (a_i << 2) < 4
            assert!(left_acc - (prev_left_acc * bls_four) < bls_four);
            // b_{i+1} - (b_i << 2) < 4
            assert!(right_acc - (prev_right_acc * bls_four) < bls_four);
            // d_{i+1} - (d_i << 2) < 4
            assert!(out_acc - (prev_out_acc * bls_four) < bls_four);

            // Get witnesses pointing to the accumulated values.
            let wit_a = self.append_witness(left_acc);
            let wit_b = self.append_witness(right_acc);
            let wit_c = self.append_witness(prod_quad_bls);
            let wit_d = self.append_witness(out_acc);
            // Add the witnesses to the witness map linking them to it's
            // corresponding gate index.
            //
            // Note that by doing this, we are basically setting the wire_coeffs
            // of the wire polynomials, but we still need to link the
            // selector_poly coefficients in order to be able to
            // have complete gates.
            //
            // Also note that here we're setting left (`a_i` in above table),
            // right (`b_i`) and fourth (`d_i`) witnesses to the
            // actual gate, meanwhile we set out (`w_i`) to the
            // previous gate.
            self.perm.add_witness_to_map(wit_a, WireData::Left(self.n));
            self.perm.add_witness_to_map(wit_b, WireData::Right(self.n));
            self.perm
                .add_witness_to_map(wit_d, WireData::Fourth(self.n));
            self.perm
                .add_witness_to_map(wit_c, WireData::Output(self.n - 1));
            // Push the witnesses to it's actual wire vector storage
            self.a_w.push(wit_a);
            self.b_w.push(wit_b);
            self.c_w.push(wit_c);
            self.d_w.push(wit_d);
            // Update the gate index
            self.n += 1;
        }

        // We have one missing value for the last row of the program memory
        // which is `c_w` since the rest of wires are pointing one gate
        // ahead. To fix this, we simply pad with a 0 so the last row of
        // the program memory will look like this:
        // | an  | bn  | 0   | dn  |
        self.perm.add_witness_to_map(
            Self::constant_zero(),
            WireData::Output(self.n - 1),
        );
        self.c_w.push(Self::constant_zero());

        // Now the wire values are set for each gate, indexed and mapped in the
        // `witness_map` inside of the `Permutation` struct.
        // Now we just need to extend the selector polynomials with the
        // appropriate coefficients to form complete logic gates.
        for _ in 0..num_quads {
            self.q_m.push(BlsScalar::zero());
            self.q_l.push(BlsScalar::zero());
            self.q_r.push(BlsScalar::zero());
            self.q_arith.push(BlsScalar::zero());
            self.q_o.push(BlsScalar::zero());
            self.q_4.push(BlsScalar::zero());
            self.q_range.push(BlsScalar::zero());
            self.q_fixed_group_add.push(BlsScalar::zero());
            self.q_variable_group_add.push(BlsScalar::zero());
            match is_component_xor {
                true => {
                    self.q_c.push(-BlsScalar::one());
                    self.q_logic.push(-BlsScalar::one());
                }
                false => {
                    self.q_c.push(BlsScalar::one());
                    self.q_logic.push(BlsScalar::one());
                }
            };
        }
        // For the last gate, `q_c` and `q_logic` we use no-op values (Zero).
        self.q_m.push(BlsScalar::zero());
        self.q_l.push(BlsScalar::zero());
        self.q_r.push(BlsScalar::zero());
        self.q_arith.push(BlsScalar::zero());
        self.q_o.push(BlsScalar::zero());
        self.q_4.push(BlsScalar::zero());
        self.q_range.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());

        self.q_c.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());

        // Now we check that the last gates wire coefficients match the
        // original values introduced in the function taking into account the
        // bit_num specified on the fn call parameters.
        // To make sure we only check the bits that are specified by bit_num, we
        // apply a bit_mask to the values.
        // Note that we can not construct a `bit_mask` that represents the
        // `BlsScalar` made from four `u64::MAX` which would be needed for
        // `num_bits = 256`. This is because `BlsScalar` created `from_raw` are
        // invalid if their value exceeds the `MODULO`.
        match num_bits < 256 {
            true => {
                let bit_mask =
                    BlsScalar::from(2u64).pow(&[num_bits as u64, 0, 0, 0])
                        - BlsScalar::one();
                assert_eq!(
                    self.witnesses[&a] & bit_mask,
                    self.witnesses[&self.a_w[self.n - 1]],
                );
                assert_eq!(
                    self.witnesses[&b] & bit_mask,
                    self.witnesses[&self.b_w[self.n - 1]]
                );
            }
            false => {
                assert_eq!(
                    self.witnesses[&a],
                    self.witnesses[&self.a_w[self.n - 1]],
                );
                assert_eq!(
                    self.witnesses[&b],
                    self.witnesses[&self.b_w[self.n - 1]]
                );
            }
        }
        // Once the inputs are checked against the accumulated additions,
        // we can safely return the resulting witness of the gate computation
        // which is stored on the last program memory row and in the column that
        // `d_w` is holding.
        self.d_w[self.d_w.len() - 1]
    }

    /// Adds a logical XOR gate that performs the XOR between two values for the
    /// specified first `num_bits` returning a [`Witness`] holding the
    /// result.
    ///
    /// # Panics
    ///
    /// If the `num_bits` specified in the fn params is odd.
    pub fn component_xor(
        &mut self,
        a: Witness,
        b: Witness,
        num_bits: usize,
    ) -> Witness {
        self.logic_gate(a, b, num_bits, true)
    }

    /// Adds a logical AND gate that performs the bitwise AND between two values
    /// for the specified first `num_bits` returning a [`Witness`]
    /// holding the result.
    ///
    /// # Panics
    ///
    /// If the `num_bits` specified in the fn params is odd.
    pub fn component_and(
        &mut self,
        a: Witness,
        b: Witness,
        num_bits: usize,
    ) -> Witness {
        self.logic_gate(a, b, num_bits, false)
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use dusk_bls12_381::BlsScalar;
    #[test]
    fn logic_xor() {
        let res = gadget_tester(
            |composer| {
                let a = BlsScalar::from_raw([
                    0xffefffff00000001,
                    0x53bda402fffe5bfe,
                    0x4982789dacb42eba,
                    0xbfe253acde2f251b,
                ]);
                let b = BlsScalar::from_raw([
                    0x1fe4fa89f2eebc13,
                    0x19420effaad6cb43,
                    0xfe10a3b5d02ccba5,
                    0x2979075741adef02,
                ]);
                let witness_a = composer.append_witness(a);
                let witness_b = composer.append_witness(b);
                let bit_num = 32 * 8 - 2;
                let xor_res =
                    composer.component_xor(witness_a, witness_b, bit_num);
                // Check that the XOR result is indeed what we are expecting.
                let bit_mask =
                    BlsScalar::from(2).pow(&[bit_num as u64, 0, 0, 0])
                        - BlsScalar::one();
                composer.assert_equal_constant(
                    xor_res,
                    (a ^ b) & bit_mask,
                    None,
                );
            },
            900,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn logic_and() {
        let res = gadget_tester(
            |composer| {
                let a = BlsScalar::from_raw([
                    0xcdbbba32b2059321,
                    0xd23d790abc203def,
                    0x039290023244ddd2,
                    0x221045dddbaaa234,
                ]);
                let b = BlsScalar::from_raw([
                    0xffeffa89f2eebc13,
                    0x19420effaad6cb43,
                    0x0000138739efccab,
                    0x2979bc292cccde11,
                ]);
                let witness_a = composer.append_witness(a);
                let witness_b = composer.append_witness(b);
                let bit_num = 32 * 8;
                let and_res =
                    composer.component_and(witness_a, witness_b, bit_num);
                // Check that the XOR result is indeed what we are expecting.
                composer.assert_equal_constant(and_res, a & b, None);
            },
            500,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_logic_xor_and_constraint_small() {
        // Should pass since the XOR result is correct and the bit-num is even.
        let res = gadget_tester(
            |composer| {
                let a = 500u64;
                let b = 357u64;
                let bit_num = 10;
                let witness_a = composer.append_witness(BlsScalar::from(a));
                let witness_b = composer.append_witness(BlsScalar::from(b));
                let xor_res =
                    composer.component_xor(witness_a, witness_b, bit_num);
                // Check that the XOR result is indeed what we are expecting.
                composer.assert_equal_constant(
                    xor_res,
                    BlsScalar::from(a ^ b),
                    None,
                );
            },
            200,
        );
        assert!(res.is_ok());

        // Should pass since the AND result is correct and the bit-num is even.
        let res = gadget_tester(
            |composer| {
                let a = 0x2979bc292cccde11;
                let b = 0x5792abc4d3002eda;
                // fails if I want to compare 32 * 8 bits but passes like this
                let bit_num = 32 * 8 - 2;
                let witness_a = composer.append_witness(BlsScalar::from(a));
                let witness_b = composer.append_witness(BlsScalar::from(b));
                let and_res =
                    composer.component_and(witness_a, witness_b, bit_num);
                // Check that the AND result is indeed what we are expecting.
                composer.assert_equal_constant(
                    and_res,
                    BlsScalar::from(a & b),
                    None,
                );
            },
            700,
        );
        assert!(res.is_ok());

        // Should not pass since the XOR result is not correct even the bit-num
        // is even.
        let res = gadget_tester(
            |composer| {
                let a = 139u64;
                let b = 33u64;
                let bit_num = 10;
                let witness_a = composer.append_witness(BlsScalar::from(a));
                let witness_b = composer.append_witness(BlsScalar::from(b));
                let and_res =
                    composer.component_and(witness_a, witness_b, bit_num);
                // AND result should not pass
                composer.assert_equal_constant(
                    and_res,
                    BlsScalar::from(a ^ b),
                    None,
                );
            },
            200,
        );
        assert!(res.is_err());

        // Should pass even if the bit-num is less than the number bit-size
        let res = gadget_tester(
            |composer| {
                let a = 256u64;
                let b = 0xd23d790abc203def;
                let bit_num = 60;
                let witness_a = composer.append_witness(BlsScalar::from(a));
                let witness_b = composer.append_witness(BlsScalar::from(b));
                let xor_res =
                    composer.component_xor(witness_a, witness_b, bit_num);
                // Check that the XOR result is indeed what we are expecting.
                let bit_mask =
                    BlsScalar::from(2).pow(&[bit_num as u64, 0, 0, 0])
                        - BlsScalar::one();
                composer.assert_equal_constant(
                    xor_res,
                    BlsScalar::from(a ^ b) & BlsScalar::from(bit_mask),
                    None,
                );
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_logical_gate_odd_bit_num() {
        // Should fail since the bit-num is odd.
        let _ = gadget_tester(
            |composer| {
                let witness_a =
                    composer.append_witness(BlsScalar::from(500u64));
                let witness_b =
                    composer.append_witness(BlsScalar::from(499u64));
                let xor_res = composer.component_xor(witness_a, witness_b, 9);
                // Check that the XOR result is indeed what we are expecting.
                composer.assert_equal_constant(
                    xor_res,
                    BlsScalar::from(7u64),
                    None,
                );
            },
            200,
        );
    }
}
