// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Truncation gadgets: the canonical `high`/`low` split of a field element at
//! a given bit position, and the public entry point that exposes it.

use dusk_bls12_381::BlsScalar;

use super::bits::recompose_bits;
use super::{Composer, Constraint, Witness};

/// Truncation gadgets
impl Composer {
    /// Bind an already-bounded `low` to the low `num_bits` of `input` via the
    /// canonical truncation split `input = high * 2^num_bits + low`.
    ///
    /// Derives `high` from `input`, range-checks it to
    /// `[0, 2^(255 - num_bits))`, enforces the linear relation, and adds the
    /// canonical `< r` guard so the split cannot alias `input + r`. The caller
    /// MUST already constrain `low` to `[0, 2^num_bits)` — with a range check,
    /// or through the logic gate for the logic gadget — otherwise the split is
    /// not unique and the binding is unsound. Shared core of
    /// [`Self::component_truncate`] and [`Self::bind_truncated_input`].
    pub(super) fn bind_truncation_split(
        &mut self,
        input: Witness,
        low: Witness,
        num_bits: usize,
    ) {
        // A canonical field element is < 2^255, so its high part fits in
        // `255 - num_bits` bits.
        let high_bits = 255 - num_bits;
        let pow = BlsScalar::pow_of_2(num_bits as u64);

        // high = floor(input / 2^num_bits), recomposed from the high input
        // bits, range-checked so it cannot absorb a different low part.
        let input_bits = self[input].to_bits();
        let high_value = recompose_bits(&input_bits, num_bits, 256);
        let high = self.append_witness(high_value);
        self.range_check(high, high_bits);

        // input == high * 2^num_bits + low
        let recomposed =
            self.gate_add(Constraint::new().left(pow).right(1).a(high).b(low));
        self.assert_equal(recomposed, input);

        // The linear relation above also admits the non-canonical assignment
        // that recomposes to `input + r` (a small `high` with a different
        // `low`, both still in range), decoupling `low` from `input`. The
        // canonical guard rejects exactly that alias, pinning `low` to the
        // integer reduction.
        self.assert_canonical_truncation(high, low, num_bits);
    }

    /// Extract the low `N` bits of `witness` as a new [`Witness`], canonically
    /// bound to its input.
    ///
    /// This is the truncation primitive: it proves `low = witness mod 2^N`
    /// directly via the relation `witness = high * 2^N + low`, with a range
    /// check on `low` (`N` bits), a range check on `high` (the remaining
    /// `255 - N` bits), the linear binding gate, and a canonical `< r` guard so
    /// the `(high, low)` split cannot alias the non-canonical representation
    /// `witness + r`. `N` may be odd.
    ///
    /// `append_logic_xor::<BIT_PAIRS>(witness, ZERO)` also yields the low bits,
    /// but it is a bitwise operator pressed into a truncation role: it pays for
    /// the full bitwise widget over the discarded high bits and its width is a
    /// bit-pair count, not a bit count. Prefer `component_truncate` when the
    /// intent is "take the low `N` bits"; reach for the logic gate when the
    /// intent is an actual bitwise `XOR`.
    ///
    /// Cost: the gadget range-checks the full `N + (255 - N)` split plus a
    /// same-width canonical guard, so the decomposed width — and with it the
    /// gate count — is essentially independent of `N`: 84-88 gates across the
    /// whole range. That is cheaper than `append_logic_xor::<N / 2>(x, ZERO)`
    /// at every width, and the gap widens with `N`, since the logic gadget pays
    /// for its per-quad loop on top of the same binding: 88 against 172 gates
    /// at 2 bits, 88 against 234 at 250.
    ///
    /// `N` is capped at `254` at compile time: a canonical `BlsScalar` is 255
    /// bits, so a wider truncation would leave the high part with less than one
    /// bit and the canonical guard ill-defined.
    pub fn component_truncate<const N: usize>(
        &mut self,
        witness: Witness,
    ) -> Witness {
        // A canonical `BlsScalar` is 255 bits, so the truncation binding below
        // is only canonical up to 254 bits. A wider width would silently drop
        // input bits, so it is a hard compile-time error rather than a quiet
        // cap.
        const {
            assert!(
                N <= 254,
                "N must be <= 254: truncation operates on at most 254 bits"
            )
        };

        // Split the low `N` bits off `witness` as a bounded witness, then bind
        // it back to `witness` through the shared truncation split.
        let low_value = recompose_bits(&self[witness].to_bits(), 0, N);
        let low = self.append_witness(low_value);
        self.range_check(low, N);
        self.bind_truncation_split(witness, low, N);

        low
    }

    /// Constrain `(high, low)` to be the canonical split of a field element at
    /// bit `num_bits`, i.e. `high * 2^num_bits + low < r`. This adds only the
    /// `< r` guard, rejecting the single non-canonical alias `witness + r`; it
    /// does not bound `low` or `high` itself.
    ///
    /// Caller MUST range-check both operands before calling — `low` to
    /// `[0, 2^num_bits)` and `high` to `[0, 2^(255 - num_bits))` — otherwise
    /// the split is not unique and the binding is unsound. This is the
    /// shared core for every truncation caller; the obligation is not
    /// enforced in-gate.
    pub(super) fn assert_canonical_truncation(
        &mut self,
        high: Witness,
        low: Witness,
        num_bits: usize,
    ) {
        let high_bits = 255 - num_bits;

        // Modulus-derived bounds: write `r - 1 = r_high * 2^num_bits + r_low`.
        // The split is canonical (i.e. `< r`, not `< 2r`) iff `(high, low) <=
        // (r_high, r_low)` lexicographically.
        let modulus_bits = (-BlsScalar::one()).to_bits();
        let r_low = recompose_bits(&modulus_bits, 0, num_bits);
        let r_high = recompose_bits(&modulus_bits, num_bits, 256);

        // Enforce `high <= r_high` via `diff = r_high - high in [0,
        // 2^high_bits)`.
        let diff = self.gate_add(
            Constraint::new()
                .left(-BlsScalar::one())
                .a(high)
                .constant(r_high),
        );
        self.range_check(diff, high_bits);

        // is_top = 1 iff high == r_high (diff == 0). Standard is-zero gadget:
        // set `product = diff * inverse` and `is_top = 1 - product`, then the
        // final gate `diff * is_top = 0` pins everything.
        let diff_inverse = self[diff].invert().unwrap_or(BlsScalar::zero());
        let inverse = self.append_witness(diff_inverse);
        let product =
            self.gate_mul(Constraint::new().mult(1).a(diff).b(inverse));
        // is_top = 1 - product
        let is_top = self.gate_add(
            Constraint::new()
                .left(-BlsScalar::one())
                .a(product)
                .constant(1),
        );
        // diff * is_top = 0. This alone pins is_top to exactly `[diff == 0]`,
        // so no explicit `component_boolean(is_top)` is needed. If diff == 0,
        // then product = 0 and is_top = 1 - 0 = 1. If diff != 0, this gate
        // forces is_top = 0, which forces product = 1 and hence the prover to
        // supply inverse = diff^-1. Either way is_top is 0 or 1; no other value
        // satisfies the system, so a boolean constraint would be redundant.
        self.append_gate(Constraint::new().mult(1).a(diff).b(is_top));

        // When high == r_high, require low <= r_low (so the value is < r). The
        // guard is `is_top * (r_low - low)`, which must lie in `[0,
        // 2^num_bits)`: for `low > r_low` it underflows to a huge field
        // element and fails the range check; for `high < r_high` it is zero
        // (canonicity already holds).
        let r_low_minus_low = self.gate_add(
            Constraint::new()
                .left(-BlsScalar::one())
                .a(low)
                .constant(r_low),
        );
        let guard = self
            .gate_mul(Constraint::new().mult(1).a(is_top).b(r_low_minus_low));
        self.range_check(guard, num_bits);
    }
}
