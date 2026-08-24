// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Range-check gadgets: the shared base-4 decomposition and the two public
//! entry points that delegate to it.

use alloc::vec::Vec;
use core::cmp;

use dusk_bls12_381::BlsScalar;

use super::bits::recompose_bits;
use super::{Composer, Constraint, WiredWitness, Witness};
use crate::bit_iterator::BitIterator8;

/// Range-check gadgets
impl Composer {
    /// Constrains a [`Witness`] to the range `[0, 2^BITS)`, for any (possibly
    /// odd) compile-time `BITS` up to `256`.
    ///
    /// This is the bit-width-native range check. Even widths use the base-4
    /// quad decomposition; an odd width peels off the most-significant bit as a
    /// boolean and quad-checks the even remainder, so the cost is essentially
    /// that of the even check.
    ///
    /// Prefer this over the bit-pair-counted [`Self::component_range`]: `BITS`
    /// is the actual bit width, with no `× 2` to track.
    ///
    /// A canonical `BlsScalar` is below `2^255`, so any `BITS >= 255` is
    /// satisfied by every witness: the check still emits its gates but
    /// constrains nothing.
    pub fn component_range_bits<const BITS: usize>(
        &mut self,
        witness: Witness,
    ) {
        // `range_check` recomposes a witness < 2^256, so wider checks are
        // meaningless; reject them at compile time rather than silently
        // capping.
        const {
            assert!(
                BITS <= 256,
                "BITS must be <= 256: a witness is at most 256 bits wide"
            )
        };

        self.range_check(witness, BITS);
    }

    /// Adds a range-constraint gate that checks and constrains a [`Witness`]
    /// to be encoded in at most `num_bits = BIT_PAIRS * 2` bits, which means
    /// that the underlying [`BlsScalar`] of the [`Witness`] will be within the
    /// range `[0, 2^num_bits[`, where `num_bits` is dividable by two.
    ///
    /// This function adds:
    /// (num_bits - 1)/8 + 9 gates, when num_bits > 0,
    /// and 7 gates, when num_bits = 0
    /// to the circuit description.
    /// Widths above `BIT_PAIRS = 128` are clamped to 256 bits rather than
    /// rejected, so they all mean the same check.
    #[deprecated(note = "this counts bit-pairs, an easy 2x footgun. Use \
        `component_range_bits::<BITS>`, which counts bits directly: for \
        `N <= 128` replace `component_range::<N>` with \
        `component_range_bits::<2 * N>`; a wider `N` was clamped to 256 bits, \
        so it becomes `component_range_bits::<256>`.")]
    pub fn component_range<const BIT_PAIRS: usize>(
        &mut self,
        witness: Witness,
    ) {
        // Delegates to the shared base-4 core: `BIT_PAIRS` bit-pairs is `2 *
        // BIT_PAIRS` bits, capped at 256. The core emits the same base-4
        // decomposition this entry point checks, so the gate layout — and thus
        // the verifier key — is identical for every caller.
        self.range_check_even(witness, cmp::min(BIT_PAIRS * 2, 256));
    }

    /// Constrain `value` to lie in `[0, 2^num_bits)`, for any (possibly odd)
    /// runtime `num_bits`. A runtime-sized, odd-capable counterpart to
    /// [`Self::component_range`], whose `const BIT_PAIRS` entry point can only
    /// size even widths known at compile time.
    ///
    /// Even widths use the quad-based [`Self::range_check_even`] (the same
    /// width-4 base-4 decomposition as `component_range`); an odd width peels
    /// off the most-significant bit as a boolean and quad-checks the even
    /// remainder, so the cost is essentially that of the even check.
    pub(super) fn range_check(&mut self, value: Witness, num_bits: usize) {
        if num_bits.is_multiple_of(2) {
            self.range_check_even(value, num_bits);
            return;
        }

        // value == lower + top_bit * 2^(num_bits - 1), with `lower` in
        // `[0, 2^(num_bits - 1))` and `top_bit` boolean — so value <
        // 2^num_bits.
        let top = num_bits - 1;
        let value_bits = self[value].to_bits();
        let lower_value = recompose_bits(&value_bits, 0, top);
        let top_bit_value = BlsScalar::from(value_bits[top] as u64);

        let lower = self.append_witness(lower_value);
        self.range_check_even(lower, top);

        let top_bit = self.append_witness(top_bit_value);
        self.component_boolean(top_bit);

        let recomposed = self.gate_add(
            Constraint::new()
                .left(1)
                .right(BlsScalar::pow_of_2(top as u64))
                .a(lower)
                .b(top_bit),
        );
        self.assert_equal(recomposed, value);
    }

    /// Constrain `value` to lie in `[0, 2^num_bits)` for an even runtime
    /// `num_bits` (`<= 256`). This is the shared base-4 decomposition that
    /// [`Self::component_range`] and the even path of [`Self::range_check`]
    /// delegate to — the single source of truth for the width-4 range layout.
    fn range_check_even(&mut self, witness: Witness, num_bits: usize) {
        // if num_bits = 0 constrain witness to 0
        if num_bits == 0 {
            let constraint = Constraint::new().left(1).a(witness);
            self.append_gate(constraint);
            return;
        }

        // convert witness to bit representation and reverse
        let bits = self[witness];
        let bit_iter = BitIterator8::new(bits.to_bytes());
        let mut bits: Vec<_> = bit_iter.collect();
        bits.reverse();

        // each gate holds 4 quads (2 bits each), so one gate accumulates 8 bits
        let mut num_gates = num_bits >> 3;
        if !num_bits.is_multiple_of(8) {
            num_gates += 1;
        }

        // a gate holds 4 quads
        let num_quads = num_gates * 4;

        // the wires are left-padded with the difference between the quads count
        // and the bits argument
        let pad = 1 + (((num_quads << 1) - num_bits) >> 1);

        // last gate is reserved for either the genesis quad or the padding
        let used_gates = num_gates + 1;

        let base = Constraint::range(&Constraint::new());
        let mut constraints = vec![base; used_gates];

        let mut accumulators: Vec<Witness> = Vec::new();
        let mut accumulator = BlsScalar::zero();
        let four = BlsScalar::from(4);

        for i in pad..=num_quads {
            // convert each pair of bits to quads
            let bit_index = (num_quads - i) << 1;
            let q_0 = bits[bit_index] as u64;
            let q_1 = bits[bit_index + 1] as u64;
            let quad = q_0 + (2 * q_1);

            accumulator = four * accumulator;
            accumulator += BlsScalar::from(quad);

            let accumulator_var = self.append_witness(accumulator);
            accumulators.push(accumulator_var);

            let idx = i / 4;
            // wires fill D, C, B, A within each gate as `i` advances
            let wire = [
                WiredWitness::D,
                WiredWitness::C,
                WiredWitness::B,
                WiredWitness::A,
            ][i % 4];

            constraints[idx].set_witness(wire, accumulator_var);
        }

        // last constraint is zeroed as it is reserved for the genesis quad or
        // padding
        if let Some(c) = constraints.last_mut() {
            *c = Constraint::new();
        }

        if let Some(accumulator) = accumulators.last()
            && let Some(c) = constraints.last_mut()
        {
            c.set_witness(WiredWitness::D, *accumulator);
        }

        constraints
            .into_iter()
            .for_each(|c| self.append_custom_gate(c));

        if let Some(accumulator) = accumulators.last() {
            self.assert_equal(*accumulator, witness);
        }
    }
}
