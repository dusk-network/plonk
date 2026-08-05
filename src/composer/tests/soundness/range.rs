// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Regressions for the base-4 range check and its two public entry points.
//!
//! `range_check` is the shared core every truncation binding leans on for its
//! `low`/`high` bounds, so its exact admitted interval is a soundness
//! parameter, not an implementation detail. `component_range` (deprecated,
//! bit-pair-counted) and `component_range_bits` (bit-counted) now both delegate
//! to that core, and the deprecation note promises callers the migration
//! between them leaves every verifier key untouched.
//!
//! These tests pin all three: the interval `range_check` admits, the equality
//! of the two entry points, and — against a golden captured before the
//! delegation existed — that the shared core still emits the layout the
//! deployed keys were generated against.

use dusk_bls12_381::BlsScalar;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{assert_rejected, assert_verifies, gate_digest};
use crate::composer::Composer;
use crate::prelude::{
    Circuit, Compiler, Error, Prover, PublicParameters, Verifier,
};

// A bare range check, used to pin `range_check`'s bounds directly.
struct RangeCircuit<const NUM_BITS: usize> {
    value: BlsScalar,
}

impl<const NUM_BITS: usize> Default for RangeCircuit<NUM_BITS> {
    fn default() -> Self {
        Self {
            value: BlsScalar::zero(),
        }
    }
}

impl<const NUM_BITS: usize> Circuit for RangeCircuit<NUM_BITS> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let value = composer.append_witness(self.value);
        composer.range_check(value, NUM_BITS);
        Ok(())
    }
}

// `range_check` admits exactly `[0, 2^NUM_BITS)`: `2^NUM_BITS - 1` proves,
// `2^NUM_BITS` does not.
fn assert_range_check_bounds<const NUM_BITS: usize>(
    pp: &PublicParameters,
    rng: &mut StdRng,
) {
    let (prover, verifier): (Prover, Verifier) =
        Compiler::compile::<RangeCircuit<NUM_BITS>>(pp, b"range")
            .expect("compile");

    let in_range = RangeCircuit::<NUM_BITS> {
        value: BlsScalar::pow_of_2(NUM_BITS as u64) - BlsScalar::one(),
    };
    assert_verifies(&prover, &verifier, rng, &in_range);

    let out_of_range = RangeCircuit::<NUM_BITS> {
        value: BlsScalar::pow_of_2(NUM_BITS as u64),
    };
    assert_rejected(
        &prover,
        rng,
        &in_range,
        &out_of_range,
        "2^NUM_BITS is out of range",
    );
}

#[test]
fn range_check_enforces_exact_bounds() {
    let mut rng = StdRng::seed_from_u64(0x4a_06e);
    let pp = PublicParameters::setup(1 << 8, &mut rng).expect("setup");

    assert_range_check_bounds::<6>(&pp, &mut rng); // even
    assert_range_check_bounds::<7>(&pp, &mut rng); // odd
    assert_range_check_bounds::<1>(&pp, &mut rng); // odd, minimal
}

// The deprecated `component_range::<BIT_PAIRS>` and its replacement
// `component_range_bits::<2 * BIT_PAIRS>` must emit a byte-identical gate
// sequence (selectors AND wiring, not just gate count) — both delegate to the
// shared base-4 core, and this is the contract the deprecation note promises
// callers: migrating `::<N>` (bit-pairs) to `::<2 * N>` (bits) does not change
// any verifier key. `Gate` is `PartialEq`, so the whole constraint vector is
// compared, across widths including the deployed 64-bit phoenix caller
// (`BIT_PAIRS = 32`) and the 256-bit cap.
//
// This is the one test that exercises the deprecated `component_range`; the
// `#[allow(deprecated)]` is intentional — it is a regression guard for a
// still-public, still-supported gadget, not a use to be migrated away.
#[allow(deprecated)]
#[test]
fn component_range_migration_is_gate_identical() {
    let value = -BlsScalar::one(); // every bit set, so all quads are exercised

    macro_rules! assert_layout_eq {
        ($bit_pairs:literal) => {{
            let mut bit_pairs = Composer::initialized();
            let w = bit_pairs.append_witness(value);
            bit_pairs.component_range::<$bit_pairs>(w);

            let mut bits = Composer::initialized();
            let w = bits.append_witness(value);
            bits.component_range_bits::<{ $bit_pairs * 2 }>(w);

            assert_eq!(
                bit_pairs.constraints,
                bits.constraints,
                "component_range::<{}> must match component_range_bits::<{}>",
                $bit_pairs,
                $bit_pairs * 2,
            );
        }};
    }

    assert_layout_eq!(0); // 0 bits, the N=254 high part (degenerate branch)
    assert_layout_eq!(1); // 2 bits
    assert_layout_eq!(2); // 4 bits, the N=250 high part
    assert_layout_eq!(4); // 8 bits, one full gate
    assert_layout_eq!(16); // 32 bits
    assert_layout_eq!(32); // 64 bits, the deployed phoenix money-range caller
    assert_layout_eq!(125); // 250 bits, the Schnorr width
    assert_layout_eq!(127); // 254 bits, the cap
    assert_layout_eq!(128); // 256 bits, component_range's max (capped width)
}

// `component_range_migration_is_gate_identical` compares `component_range`
// against `component_range_bits`, but both now delegate to the shared
// `range_check_even` core — so it only proves the two entry points agree, not
// that the shared core still emits the gate layout the deployed verifier keys
// were generated against. A drift in the core would change both identically and
// slip through. This pins `component_range` to a `gate_digest` golden captured
// from `component_range` as released in `v0.22.1` (`f63cfb0`), before it
// delegated — the only non-circular reference. `BIT_PAIRS = 32` is the deployed
// phoenix money-range caller (`component_range::<32>` = 2^64); if this digest
// changes, that circuit's verifier key changed.
#[allow(deprecated)]
#[test]
fn component_range_layout_matches_deployed_golden() {
    // `gate_digest`s captured from `component_range::<BIT_PAIRS>(-1)` as
    // released in `v0.22.1` (`f63cfb0`), the pre-delegation implementation.
    const GOLDEN_16: [u8; 32] = [
        77, 31, 113, 140, 168, 100, 230, 119, 141, 149, 133, 230, 149, 247,
        247, 146, 198, 131, 151, 72, 86, 226, 37, 227, 151, 105, 226, 40, 34,
        107, 152, 55,
    ];
    const GOLDEN_32: [u8; 32] = [
        211, 119, 147, 191, 124, 192, 26, 156, 231, 67, 118, 215, 252, 91, 144,
        70, 167, 7, 86, 187, 217, 252, 99, 197, 167, 153, 185, 163, 50, 167, 5,
        33,
    ];
    const GOLDEN_128: [u8; 32] = [
        61, 254, 139, 94, 245, 111, 49, 233, 147, 232, 116, 107, 73, 148, 236,
        197, 128, 124, 52, 202, 152, 56, 66, 82, 119, 96, 65, 141, 195, 208,
        155, 98,
    ];

    macro_rules! assert_golden_eq {
        ($bit_pairs:literal, $expected:expr) => {{
            let mut composer = Composer::initialized();
            let witness = composer.append_witness(-BlsScalar::one());
            composer.component_range::<$bit_pairs>(witness);
            assert_eq!(
                gate_digest(&composer.constraints),
                $expected,
                "component_range::<{}> gate layout drifted from the deployed \
                 verifier key",
                $bit_pairs,
            );
        }};
    }

    assert_golden_eq!(16, GOLDEN_16);
    assert_golden_eq!(32, GOLDEN_32); // deployed phoenix 2^64 money range
    assert_golden_eq!(128, GOLDEN_128); // capped width
}
