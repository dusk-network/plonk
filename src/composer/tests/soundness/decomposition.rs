// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regressions for `component_decomposition`: its bits must be
//! boolean, and from 255 bits up its canonical guard must reject the bit
//! strings of `x + r`, which also recompose to `x` in the field.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{assert_rejected, assert_verifies, gate_digest};
use crate::composer::bits::recompose_bits;
use crate::composer::{Composer, Witness};
use crate::prelude::{Circuit, Compiler, Error, PublicParameters};

#[derive(Default)]
struct Decomposition<const N: usize> {
    input: BlsScalar,
    bits: Option<[u8; 256]>,
}

impl<const N: usize> Circuit for Decomposition<N> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let input = composer.append_public(self.input);
        let _: [Witness; N] = match &self.bits {
            None => composer.component_decomposition(input),
            Some(bits) => composer.decompose_bits(input, bits),
        };
        Ok(())
    }
}

/// Proves the honest decomposition of `input` at width `N` and rejects each
/// forgery: an input claimed with the bit values it is decomposed into.
fn assert_forgeries_rejected<const N: usize>(
    input: BlsScalar,
    forgeries: &[(&str, BlsScalar, [u8; 256])],
) {
    let mut rng = StdRng::seed_from_u64(0xdec0);
    let pp = PublicParameters::setup(1 << 11, &mut rng).expect("setup");
    let (prover, verifier) =
        Compiler::compile::<Decomposition<N>>(&pp, b"decomposition")
            .expect("compile");

    let honest = Decomposition::<N> { input, bits: None };
    assert_verifies(&prover, &verifier, &mut rng, &honest);

    for (case, input, bits) in forgeries {
        let forged = Decomposition::<N> {
            input: *input,
            bits: Some(*bits),
        };
        assert_rejected(&prover, &mut rng, &honest, &forged, case);
    }
}

/// Proves the honest decomposition of `-1` at width `N` and rejects each
/// forged bit string.
fn assert_canonical<const N: usize>(forgeries: &[(&str, [u8; 256])]) {
    let forgeries: Vec<_> = forgeries
        .iter()
        .map(|(case, bits)| (*case, recompose_bits(bits, 0, 256), *bits))
        .collect();
    assert_forgeries_rejected::<N>(-BlsScalar::one(), &forgeries);
}

/// `sum bits[i] * 2^i` in the field, for any bit values: unlike
/// [`recompose_bits`], a value other than one still counts.
fn weighted_sum(bits: &[u8; 256]) -> BlsScalar {
    bits.iter()
        .enumerate()
        .fold(BlsScalar::zero(), |sum, (i, bit)| {
            sum + BlsScalar::from(*bit as u64) * BlsScalar::pow_of_2(i as u64)
        })
}

#[test]
fn decomposition_rejects_noncanonical_bits() {
    // `2^255 - 1 > r` in bits `0..255`, caught by the `< r` guard at both
    // widths, and `2^255` in bit 255 alone, caught by the top-bit constraint.
    let mut low_ones = [1u8; 256];
    low_ones[255] = 0;
    let mut top_bit = [0u8; 256];
    top_bit[255] = 1;
    assert_canonical::<255>(&[("2^255 - 1", low_ones)]);
    assert_canonical::<256>(&[("2^255 - 1", low_ones), ("2^255", top_bit)]);
}

#[test]
fn decomposition_rejects_non_boolean_bits() {
    // `3 * 2^0` and `2 * 2^7` recompose to `3` and `2^8`, but each carries a
    // bit that is not boolean, so only the boolean constraint on every bit
    // rejects them. The second claims an input that does not fit in 8 bits.
    let mut three = [0u8; 256];
    three[0] = 3;
    let mut two_at_seven = [0u8; 256];
    two_at_seven[7] = 2;
    assert_forgeries_rejected::<8>(
        BlsScalar::from(3u64),
        &[
            ("3 * 2^0", weighted_sum(&three), three),
            ("2 * 2^7", weighted_sum(&two_at_seven), two_at_seven),
        ],
    );
}

/// Pins the gate layout below the canonical guard and at both widths that
/// carry it. A guard or accumulator gate dropped from the emission leaves its
/// witness free, which no forgery through the bit seam can reach, so the
/// layout is what catches it.
#[test]
fn component_decomposition_layout_matches_golden() {
    // `gate_digest`s of `component_decomposition::<N>(-1)` as released in
    // `v0.24.0`.
    const GOLDEN_254: [u8; 32] = [
        106, 2, 178, 84, 169, 10, 63, 87, 193, 154, 96, 30, 43, 142, 230, 193,
        160, 108, 88, 48, 165, 131, 135, 61, 30, 186, 140, 99, 63, 90, 177, 16,
    ];
    const GOLDEN_255: [u8; 32] = [
        151, 108, 105, 123, 39, 103, 1, 180, 34, 249, 236, 153, 34, 239, 34,
        17, 146, 11, 51, 14, 200, 88, 76, 46, 238, 92, 211, 237, 204, 53, 227,
        25,
    ];
    const GOLDEN_256: [u8; 32] = [
        234, 137, 191, 47, 204, 22, 91, 217, 203, 214, 5, 7, 61, 127, 205, 117,
        177, 40, 150, 17, 191, 237, 16, 225, 73, 120, 62, 74, 71, 78, 51, 3,
    ];

    macro_rules! assert_golden_eq {
        ($n:literal, $expected:expr) => {{
            let mut composer = Composer::initialized();
            let input = composer.append_witness(-BlsScalar::one());
            let _: [Witness; $n] = composer.component_decomposition(input);
            assert_eq!(
                gate_digest(&composer.constraints),
                $expected,
                "component_decomposition::<{}>'s gate layout drifted from the \
                 pinned one",
                $n,
            );
        }};
    }

    assert_golden_eq!(254, GOLDEN_254);
    assert_golden_eq!(255, GOLDEN_255);
    assert_golden_eq!(256, GOLDEN_256);
}
