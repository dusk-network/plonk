// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Bitwise logic gadgets: the AND/XOR widget selected by a flag, the `and`
//! and `xor` entry points wrapping it, and the binding of the widget's
//! accumulators to its input witnesses.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;

use super::{Composer, Constraint, WiredWitness, Witness};
use crate::bit_iterator::BitIterator8;

/// Bitwise logic gadgets
impl Composer {
    /// Performs a logical AND or XOR op between the inputs provided for
    /// `num_bits = BIT_PAIRS * 2` bits (counting from the least significant).
    ///
    /// `BIT_PAIRS` is capped at `127` (254 bits): the closing truncation
    /// binding is only canonical up to 254 bits, since a canonical
    /// `BlsScalar` is 255 bits. `BIT_PAIRS > 127` would silently drop input
    /// bits, so it is rejected at **compile time** rather than truncated.
    ///
    /// Each logic op adds `BIT_PAIRS + 1` gates for the operation itself, plus
    /// the gates binding the result to the input witnesses. Per input the
    /// binding range-checks the high part and the canonical guard's two
    /// differences — a total width of `510 - num_bits` bits, so roughly
    /// `(510 - num_bits) / 8` gates plus a small fixed remainder. The binding
    /// therefore shrinks as `num_bits` grows, but the operation loop grows
    /// twice as fast, so the total rises with width: 172 gates at 2 bits, 234
    /// at 250.
    ///
    /// ## Constraint
    /// - is_component_xor = 1 -> Performs XOR between the first `num_bits` for
    ///   `a` and `b`.
    /// - is_component_xor = 0 -> Performs AND between the first `num_bits` for
    ///   `a` and `b`.
    pub fn append_logic_component<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
        is_component_xor: bool,
    ) -> Witness {
        // The bits are processed in quads (two bits each), so the width is
        // always even. It is capped at 254 — the largest even width for which
        // the closing truncation binding below is canonical (a canonical
        // `BlsScalar` is 255 bits). Exceeding `BIT_PAIRS = 127` would silently
        // drop bits, a soundness footgun, so it is a hard compile-time error
        // rather than a quiet cap.
        const {
            assert!(
                BIT_PAIRS <= 127,
                "BIT_PAIRS must be <= 127: the logic gadget operates on at most 254 bits"
            )
        };

        let num_bits = BIT_PAIRS * 2;
        let num_quads = BIT_PAIRS;

        let bls_four = BlsScalar::from(4u64);
        let mut left_acc = BlsScalar::zero();
        let mut right_acc = BlsScalar::zero();
        let mut out_acc = BlsScalar::zero();

        // skip bits outside of argument `num_bits`
        let a_bit_iter = BitIterator8::new(self[a].to_bytes());
        let a_bits: Vec<_> = a_bit_iter.skip(256 - num_bits).collect();
        let b_bit_iter = BitIterator8::new(self[b].to_bytes());
        let b_bits: Vec<_> = b_bit_iter.skip(256 - num_bits).collect();

        //
        // * +-----+-----+-----+-----+
        // * |  A  |  B  |  C  |  D  |
        // * +-----+-----+-----+-----+
        // * | 0   | 0   | w1  | 0   |
        // * | a1  | b1  | w2  | d1  |
        // * | a2  | b2  | w3  | d2  |
        // * |  :  |  :  |  :  |  :  |
        // * | an  | bn  | 0   | dn  |
        // * +-----+-----+-----+-----+
        // `an`, `bn` and `dn` are accumulators: `an [& OR ^] bd = dn`
        //
        // each step will shift last computation two bits to the left and add
        // current quad.
        //
        // `wn` product accumulators will safeguard the quotient polynomial.

        let mut constraint = if is_component_xor {
            Constraint::logic_xor(&Constraint::new())
        } else {
            Constraint::logic(&Constraint::new())
        };

        for i in 0..num_quads {
            // commit every accumulator
            let idx = i * 2;

            let l = (a_bits[idx] as u8) << 1;
            let r = a_bits[idx + 1] as u8;
            let left_quad = l + r;
            let left_quad_bls = BlsScalar::from(left_quad as u64);

            let l = (b_bits[idx] as u8) << 1;
            let r = b_bits[idx + 1] as u8;
            let right_quad = l + r;
            let right_quad_bls = BlsScalar::from(right_quad as u64);

            let out_quad_bls = if is_component_xor {
                left_quad ^ right_quad
            } else {
                left_quad & right_quad
            } as u64;
            let out_quad_bls = BlsScalar::from(out_quad_bls);

            // `w` argument to safeguard the quotient polynomial
            let prod_quad_bls = (left_quad * right_quad) as u64;
            let prod_quad_bls = BlsScalar::from(prod_quad_bls);

            // Now that we've computed this round results, we need to apply the
            // logic transition constraint that will check that
            //   a_{i+1} - (a_i << 2) < 4
            //   b_{i+1} - (b_i << 2) < 4
            //   d_{i+1} - (d_i << 2) < 4   with d_i = a_i [& OR ^] b_i
            // Note that multiplying by four is the equivalent of shifting the
            // bits two positions to the left.

            left_acc = left_acc * bls_four + left_quad_bls;
            right_acc = right_acc * bls_four + right_quad_bls;
            out_acc = out_acc * bls_four + out_quad_bls;

            let wit_a = self.append_witness(left_acc);
            let wit_b = self.append_witness(right_acc);
            let wit_c = self.append_witness(prod_quad_bls);
            let wit_d = self.append_witness(out_acc);

            constraint = constraint.c(wit_c);

            self.append_custom_gate(constraint);

            constraint = constraint.a(wit_a).b(wit_b).d(wit_d);
        }

        // pad last output with `0`
        // | an  | bn  | 0   | dn  |
        let left_acc_wit = constraint.witness(WiredWitness::A);
        let right_acc_wit = constraint.witness(WiredWitness::B);
        let d = constraint.witness(WiredWitness::D);

        let constraint =
            Constraint::new().a(left_acc_wit).b(right_acc_wit).d(d);

        self.append_custom_gate(constraint);

        // Bind the recomposed accumulators to the input witnesses. The loop
        // above constrains the accumulators only among themselves;
        // without this binding the output is decoupled from `a`/`b` and
        // a malicious prover can pick arbitrary accumulators (and thus
        // an arbitrary output) for the identical gate layout. Mirrors
        // `component_range`'s closing `assert_equal`, generalised to a
        // canonical truncation to `num_bits` bits.
        self.bind_logic_accumulators::<BIT_PAIRS>(
            a,
            b,
            left_acc_wit,
            right_acc_wit,
        );

        d
    }

    /// Bind the recomposed logic accumulators to the gadget's input witnesses.
    ///
    /// `left_acc`/`right_acc` are the final accumulators produced by
    /// [`Self::append_logic_component`]; the logic gate guarantees each lies in
    /// `[0, 2^num_bits)`. This binds them to the low `num_bits` of `a`/`b` so
    /// the output cannot be decoupled from the inputs.
    pub(super) fn bind_logic_accumulators<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
        left_acc: Witness,
        right_acc: Witness,
    ) {
        // A zero-bit logic op reads no input bits and returns `0`, so there is
        // nothing to bind.
        if BIT_PAIRS == 0 {
            return;
        }

        self.bind_truncated_input::<BIT_PAIRS>(a, left_acc);
        self.bind_truncated_input::<BIT_PAIRS>(b, right_acc);
    }

    /// Constrain `acc` to be the low `num_bits = BIT_PAIRS * 2` bits of
    /// `input` (`BIT_PAIRS <= 127`, enforced by the caller).
    ///
    /// `acc` is already constrained to `[0, 2^num_bits)` by the logic gate;
    /// this ties it to `input` through the shared truncation split.
    pub(super) fn bind_truncated_input<const BIT_PAIRS: usize>(
        &mut self,
        input: Witness,
        acc: Witness,
    ) {
        // matches the width of `append_logic_component`, which caps
        // `BIT_PAIRS` at 127 (254 bits) at compile time
        let num_bits = BIT_PAIRS * 2;
        self.bind_truncation_split(input, acc, num_bits);
    }

    /// Adds a logical AND gate that performs the bitwise AND between two
    /// values for the specified first `num_bits = BIT_PAIRS * 2` bits
    /// (`BIT_PAIRS <= 127`, max 254 bits) returning a [`Witness`] holding the
    /// result.
    pub fn append_logic_and<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
    ) -> Witness {
        self.append_logic_component::<BIT_PAIRS>(a, b, false)
    }

    /// Adds a logical XOR gate that performs the XOR between two values for
    /// the specified first `num_bits = BIT_PAIRS * 2` bits (`BIT_PAIRS <=
    /// 127`, max 254 bits) returning a [`Witness`] holding the result.
    pub fn append_logic_xor<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
    ) -> Witness {
        self.append_logic_component::<BIT_PAIRS>(a, b, true)
    }
}
