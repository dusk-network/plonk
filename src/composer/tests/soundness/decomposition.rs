// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regression for `component_decomposition`'s canonical guard: from
//! 255 bits up, bit strings of `x + r` also recompose to `x` in the field.

use dusk_bls12_381::BlsScalar;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{assert_rejected, assert_verifies};
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

/// Proves the honest decomposition of `-1` at width `N` and rejects each
/// forged bit string.
fn assert_canonical<const N: usize>(forgeries: &[(&str, [u8; 256])]) {
    let mut rng = StdRng::seed_from_u64(0xdec0);
    let pp = PublicParameters::setup(1 << 11, &mut rng).expect("setup");
    let (prover, verifier) =
        Compiler::compile::<Decomposition<N>>(&pp, b"decomposition")
            .expect("compile");

    let honest = Decomposition::<N> {
        input: -BlsScalar::one(),
        bits: None,
    };
    assert_verifies(&prover, &verifier, &mut rng, &honest);

    for (case, bits) in forgeries {
        let forged = Decomposition::<N> {
            input: recompose_bits(bits, 0, 256),
            bits: Some(*bits),
        };
        assert_rejected(&prover, &mut rng, &honest, &forged, case);
    }
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
