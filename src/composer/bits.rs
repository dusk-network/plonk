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
    /// Consumes `2 · N + 1` gates
    pub fn component_decomposition<const N: usize>(
        &mut self,
        scalar: Witness,
    ) -> [Witness; N] {
        // Static assertion
        assert!(0 < N && N <= 256);

        let mut decomposition = [Self::ZERO; N];

        let acc = Self::ZERO;
        let acc = self[scalar]
            .to_bits()
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

                self.gate_add(constraint)
            });

        self.assert_equal(acc, scalar);

        decomposition
    }
}
