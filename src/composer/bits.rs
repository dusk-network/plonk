// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Bit-level primitives the gadget modules build on: the boolean constraint,
//! the in-circuit bit decomposition, and the host-side recomposition of a bit
//! slice into a field element.

use dusk_bls12_381::BlsScalar;

use super::{Composer, Constraint, Witness};

/// Recompose `bits[start..end]` (little-endian, bit `i` weighing `2^i`) into a
/// field element with `bits[start]` as the least significant bit, i.e. the
/// value `sum_{i in [start, end)} bits[i] * 2^(i - start)`.
pub(super) fn recompose_bits(
    bits: &[u8; 256],
    start: usize,
    end: usize,
) -> BlsScalar {
    let two = BlsScalar::from(2u64);
    let mut value = BlsScalar::zero();
    for i in (start..end).rev() {
        value *= two;
        if bits[i] == 1 {
            value += BlsScalar::one();
        }
    }
    value
}

/// Bit-level primitives
impl Composer {
    /// Adds a boolean constraint (also known as binary constraint) where the
    /// gate eq. will enforce that the [`Witness`] received is either `0` or `1`
    /// by adding a constraint in the circuit.
    ///
    /// Note that using this constraint with whatever [`Witness`] that
    /// is not representing a value equalling 0 or 1, will always force the
    /// equation to fail.
    pub fn component_boolean(&mut self, a: Witness) {
        let zero = Self::ZERO;
        let constraint = Constraint::new()
            .mult(1)
            .output(-BlsScalar::one())
            .a(a)
            .b(a)
            .c(a)
            .d(zero);

        self.append_gate(constraint);
    }

    /// Decomposes `scalar` into an array truncated to `N` bits (max 256) in
    /// little endian.
    /// The `scalar` for 4, for example, would be deconstructed into the array
    /// `[0, 0, 1]` for `N = 3` and `[0, 0, 1, 0, 0]` for `N = 5`.
    ///
    /// Asserts the reconstruction of the bits to be equal to `scalar`. So with
    /// the above example, the deconstruction of 4 for `N < 3` would result in
    /// an unsatisfied circuit.
    ///
    /// For `N >= 255` the bits are also constrained to the canonical
    /// representative of `scalar`, which the recomposition alone does not do
    /// since `2^255 > r`.
    ///
    /// Consumes `2 · N + 1` gates, plus 36 for `N = 255` and 37 for `N = 256`.
    pub fn component_decomposition<const N: usize>(
        &mut self,
        scalar: Witness,
    ) -> [Witness; N] {
        self.decompose_bits(scalar, &self[scalar].to_bits())
    }

    /// [`Self::component_decomposition`] with the bit witnesses taken from
    /// `bit_values`, so tests can emit its gates with non-canonical bits.
    pub(super) fn decompose_bits<const N: usize>(
        &mut self,
        scalar: Witness,
        bit_values: &[u8; 256],
    ) -> [Witness; N] {
        // Static assertion
        assert!(0 < N && N <= 256);

        let mut decomposition = [Self::ZERO; N];
        let mut low = Self::ZERO;

        let acc = Self::ZERO;
        let acc = bit_values
            .iter()
            .enumerate()
            .zip(decomposition.iter_mut())
            .fold(acc, |acc, ((i, bit), w_bit)| {
                *w_bit = self.append_witness(BlsScalar::from(*bit as u64));

                self.component_boolean(*w_bit);

                let constraint = Constraint::new()
                    .left(BlsScalar::pow_of_2(i as u64))
                    .right(1)
                    .a(*w_bit)
                    .b(acc);

                let acc = self.gate_add(constraint);
                if i == 253 {
                    low = acc;
                }
                acc
            });

        self.assert_equal(acc, scalar);

        // Bound the bits to an integer below `r`: bit 255 is zero and, when
        // bit 254 is set, `low`, the exact sum of bits `0..254`, is at most the
        // low part of `r - 1`. This is the canonical truncation guard at bit
        // 254, where bit 254 is the whole high part and so already its
        // `high == r_high` flag.
        if N > 254 {
            decomposition[255..].iter().for_each(|bit| {
                self.assert_equal_constant(*bit, BlsScalar::zero(), None)
            });
            let r_low = recompose_bits(&(-BlsScalar::one()).to_bits(), 0, 254);
            let r_low_minus_low = self.gate_add(
                Constraint::new()
                    .left(-BlsScalar::one())
                    .a(low)
                    .constant(r_low),
            );
            let guard = self.gate_mul(
                Constraint::new()
                    .mult(1)
                    .a(decomposition[254])
                    .b(r_low_minus_low),
            );
            self.range_check(guard, 254);
        }

        decomposition
    }
}
