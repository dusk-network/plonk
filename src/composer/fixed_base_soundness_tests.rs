// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regressions for `component_mul_generator`.
//!
//! The fixed-base widget advances two accumulators from the same signed digits:
//! a scalar recurrence in the BLS scalar field and a point recurrence on
//! Jubjub. Before the scalar and digit bounds were added, 256 digits could
//! encode the BLS modulus `q`. The scalar endpoint was then `q == 0` in the
//! field while the point endpoint remained `[q]G != identity`, allowing a
//! proof of a false public scalar/point relation.
//!
//! The forgery tests compile the verifier key from the honest production
//! gadget, then use the production constraint emitter with attacker-chosen
//! digits. The forged circuits therefore have exactly the same selectors and
//! wiring as the honest circuit. The injected assignments satisfy the old
//! fixed-base transitions, the closing field equality, and the claimed public
//! point; only the new canonical-scalar or leading-zero constraint rejects
//! them. The final test builds no circuit: it pins the width bound those
//! constraints rely on to the field moduli by exact integer arithmetic.

use rand::SeedableRng;
use rand::rngs::StdRng;

use super::soundness_support::{assert_rejected, assert_verifies};
use super::*;
use crate::prelude::{
    Compiler, PlonkVersion, Prover, PublicParameters, Verifier,
};

// Canonical little-endian limbs of the BLS12-381 scalar-field modulus q.
const BLS_MODULUS: [u64; 4] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

// Canonical little-endian limbs of the Jubjub prime-subgroup modulus r.
const JUBJUB_MODULUS: [u64; 4] = [
    0xd097_0e5e_d6f7_2cb7,
    0xa668_2093_ccc8_1082,
    0x0667_3b01_0134_3b00,
    0x0e7d_b4ea_6533_afa9,
];

fn binary_digits(
    limbs: [u64; 4],
    sign: i8,
) -> [i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS] {
    let mut digits = [0i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS];
    for (limb_index, limb) in limbs.iter().enumerate() {
        for bit_index in 0..64 {
            digits[limb_index * 64 + bit_index] =
                (((limb >> bit_index) & 1) as i8) * sign;
        }
    }
    digits
}

fn signed_digit_endpoint(
    digits: &[i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
) -> BlsScalar {
    digits
        .iter()
        .rev()
        .fold(BlsScalar::zero(), |accumulator, digit| {
            let digit = match digit {
                -1 => -BlsScalar::one(),
                0 => BlsScalar::zero(),
                1 => BlsScalar::one(),
                _ => panic!("test digits must be signed binary"),
            };
            accumulator.double() + digit
        })
}

fn digit_to_scalar(digit: i8) -> BlsScalar {
    match digit {
        -1 => -BlsScalar::one(),
        0 => BlsScalar::zero(),
        1 => BlsScalar::one(),
        _ => panic!("test digits must be signed binary"),
    }
}

fn leading_endpoint(
    digits: &[i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
) -> BlsScalar {
    digits
        .iter()
        .rev()
        .take(FIXED_BASE_LEADING_ZERO_ROUNDS)
        .fold(BlsScalar::zero(), |accumulator, digit| {
            accumulator.double() + digit_to_scalar(*digit)
        })
}

fn point_from_signed_digits(
    digits: &[i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
) -> JubJubExtended {
    let mut point = JubJubExtended::identity();
    let mut multiple = dusk_jubjub::GENERATOR_EXTENDED;

    for digit in digits {
        point = match digit {
            -1 => point - multiple,
            0 => point,
            1 => point + multiple,
            _ => panic!("test digits must be signed binary"),
        };
        multiple = multiple.double();
    }

    point
}

#[derive(Clone)]
struct FixedBaseCircuit {
    scalar: BlsScalar,
    claimed_point: JubJubExtended,
    forged_digits: Option<[i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS]>,
}

impl Default for FixedBaseCircuit {
    fn default() -> Self {
        Self {
            scalar: BlsScalar::zero(),
            claimed_point: JubJubExtended::identity(),
            forged_digits: None,
        }
    }
}

impl FixedBaseCircuit {
    fn honest(scalar: JubJubScalar) -> Self {
        Self {
            scalar: BlsScalar::from(scalar),
            claimed_point: dusk_jubjub::GENERATOR_EXTENDED * scalar,
            forged_digits: None,
        }
    }

    fn forged(
        scalar: BlsScalar,
        digits: [i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
    ) -> Self {
        Self {
            scalar,
            claimed_point: point_from_signed_digits(&digits),
            forged_digits: Some(digits),
        }
    }
}

impl Circuit for FixedBaseCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let scalar = composer.append_public(self.scalar);
        let point = match &self.forged_digits {
            None => composer.component_mul_generator(
                scalar,
                dusk_jubjub::GENERATOR_EXTENDED,
            )?,
            Some(digits) => composer.append_fixed_base_signed_digits(
                scalar,
                dusk_jubjub::GENERATOR_EXTENDED,
                digits,
            )?,
        };
        composer.assert_equal_public_point(point, self.claimed_point);
        Ok(())
    }
}

fn compile(pp: &PublicParameters) -> (Prover, Verifier) {
    Compiler::compile::<FixedBaseCircuit>(pp, b"fixed-base-scalar-soundness-v3")
        .expect("compile fixed-base soundness circuit")
}

fn assert_wrap_rejected(
    prover: &Prover,
    rng: &mut StdRng,
    honest: &FixedBaseCircuit,
    public_scalar: BlsScalar,
    digits: [i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
    case: &str,
) {
    assert_eq!(
        signed_digit_endpoint(&digits),
        public_scalar,
        "{case}: the old closing field equality must pass",
    );
    assert_ne!(
        leading_endpoint(&digits),
        BlsScalar::zero(),
        "{case}: the new effective-width bound must be what rejects the wrap",
    );

    let forgery = FixedBaseCircuit::forged(public_scalar, digits);
    assert_rejected(prover, rng, honest, &forgery, case);
}

#[test]
fn fixed_base_rejects_modulus_wraps_under_v3() {
    assert_eq!(PlonkVersion::current(), PlonkVersion::V3);

    let mut rng = StdRng::seed_from_u64(0xf1_ed_ba_5e);
    let pp = PublicParameters::setup(1 << 10, &mut rng).expect("setup");
    let (prover, verifier) = compile(&pp);

    let honest = FixedBaseCircuit::default();
    assert_verifies(&prover, &verifier, &mut rng, &honest);

    // q == 0 in the BLS scalar field, while [q]G is nonidentity because q is
    // not divisible by the Jubjub subgroup order.
    let q_digits = binary_digits(BLS_MODULUS, 1);
    let q_point = point_from_signed_digits(&q_digits);
    assert_ne!(q_point, JubJubExtended::identity());
    assert_wrap_rejected(
        &prover,
        &mut rng,
        &honest,
        BlsScalar::zero(),
        q_digits,
        "q represented as public zero",
    );

    // q + 1 == 1 in the BLS scalar field.
    let mut q_plus_one = BLS_MODULUS;
    q_plus_one[0] += 1;
    assert_wrap_rejected(
        &prover,
        &mut rng,
        &honest,
        BlsScalar::one(),
        binary_digits(q_plus_one, 1),
        "q + 1 represented as public one",
    );

    // 1 - q == 1 in the BLS scalar field.
    let mut q_minus_one = BLS_MODULUS;
    q_minus_one[0] -= 1;
    assert_wrap_rejected(
        &prover,
        &mut rng,
        &honest,
        BlsScalar::one(),
        binary_digits(q_minus_one, -1),
        "1 - q represented as public one",
    );
}

#[test]
fn fixed_base_requires_a_canonical_jubjub_scalar_under_v3() {
    assert_eq!(PlonkVersion::current(), PlonkVersion::V3);

    let mut rng = StdRng::seed_from_u64(0x000c_a100_1ca1);
    let pp = PublicParameters::setup(1 << 10, &mut rng).expect("setup");
    let (prover, verifier) = compile(&pp);

    // r - 1 is the largest canonical scalar and exercises the extra top NAF
    // carry at digit 252.
    let max = FixedBaseCircuit::honest(-JubJubScalar::one());
    assert_verifies(&prover, &verifier, &mut rng, &max);

    // The integer r fits the effective signed-digit width and [r]G is the
    // identity, so every fixed-base transition and the leading-zero bound pass.
    // Only the new canonical `< r` constraint rejects it.
    let r_digits = binary_digits(JUBJUB_MODULUS, 1);
    assert_eq!(
        leading_endpoint(&r_digits),
        BlsScalar::zero(),
        "r must clear the effective signed-digit width bound",
    );
    let r = BlsScalar::from(-JubJubScalar::one()) + BlsScalar::one();
    assert_eq!(signed_digit_endpoint(&r_digits), r);
    assert_eq!(
        point_from_signed_digits(&r_digits),
        JubJubExtended::identity(),
    );

    let noncanonical = FixedBaseCircuit::forged(r, r_digits);
    assert_rejected(
        &prover,
        &mut rng,
        &max,
        &noncanonical,
        "Jubjub modulus r is noncanonical",
    );
}

fn limbs_from_canonical_bytes(bytes: [u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
    }
    limbs
}

fn checked_increment(mut limbs: [u64; 4]) -> [u64; 4] {
    for limb in &mut limbs {
        let (sum, carry) = limb.overflowing_add(1);
        *limb = sum;
        if !carry {
            return limbs;
        }
    }
    panic!("the increment must not overflow 256 bits");
}

fn checked_subtract(minuend: [u64; 4], subtrahend: [u64; 4]) -> [u64; 4] {
    let mut difference = [0u64; 4];
    let mut borrow = false;
    for ((difference_limb, minuend_limb), subtrahend_limb) in
        difference.iter_mut().zip(minuend).zip(subtrahend)
    {
        let (limb, underflowed) = minuend_limb.overflowing_sub(subtrahend_limb);
        let (limb, borrowed) = limb.overflowing_sub(borrow as u64);
        *difference_limb = limb;
        borrow = underflowed || borrowed;
    }
    assert!(
        !borrow,
        "the minuend must not be smaller than the subtrahend"
    );
    difference
}

// The largest accumulator endpoint magnitude a signed-digit width can
// produce: `2^width - 1`, with every digit at its extreme.
fn max_endpoint_magnitude(width: usize) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (limb_index, limb) in limbs.iter_mut().enumerate() {
        *limb = match width.saturating_sub(limb_index * 64) {
            0 => 0,
            bits if bits >= 64 => u64::MAX,
            bits => (1u64 << bits) - 1,
        };
    }
    limbs
}

fn bit_length(limbs: [u64; 4]) -> usize {
    for (limb_index, limb) in limbs.iter().enumerate().rev() {
        if *limb != 0 {
            return limb_index * 64 + 64 - limb.leading_zeros() as usize;
        }
    }
    0
}

fn big_endian(limbs: [u64; 4]) -> [u64; 4] {
    [limbs[3], limbs[2], limbs[1], limbs[0]]
}

/// The compile-time guard in `composer.rs` caps the effective signed-digit
/// width at a literal 254. This test derives both sides of that literal from
/// the actual field moduli — read back as exact integers from the canonical
/// encodings of `-1` in each field — so a curve or field change that
/// invalidates the bound fails here even though the width arithmetic still
/// satisfies the guard.
#[test]
fn fixed_base_width_bound_is_tight_for_the_field_moduli() {
    let bls_modulus_minus_one =
        limbs_from_canonical_bytes((-BlsScalar::one()).to_bytes());
    let jubjub_modulus_minus_one =
        limbs_from_canonical_bytes((-JubJubScalar::one()).to_bytes());

    // The hardcoded limb constants the forgery tests above rely on must be
    // the real moduli.
    assert_eq!(checked_increment(bls_modulus_minus_one), BLS_MODULUS);
    assert_eq!(checked_increment(jubjub_modulus_minus_one), JUBJUB_MODULUS);

    // The cheapest modulus wrap: an endpoint of magnitude `q - (r - 1)` is
    // congruent modulo `q` to the largest canonical Jubjub scalar. Every
    // other wrap needs a larger endpoint.
    let cheapest_wrap = checked_increment(checked_subtract(
        bls_modulus_minus_one,
        jubjub_modulus_minus_one,
    ));

    // At the widest width the compile-time guard admits, no endpoint reaches
    // a wrap — the closing scalar check is an integer equality.
    assert!(
        big_endian(max_endpoint_magnitude(FIXED_BASE_MAX_SOUND_WIDTH))
            < big_endian(cheapest_wrap),
        "the widest admitted width must be too narrow to encode a wrap",
    );

    // One more bit reaches the cheapest wrap: the bound is tight, not a
    // margin.
    assert!(
        big_endian(max_endpoint_magnitude(FIXED_BASE_MAX_SOUND_WIDTH + 1))
            >= big_endian(cheapest_wrap),
        "one more bit must encode a wrap, or the width bound is stale",
    );

    // Completeness floor: a width-2 NAF of a canonical Jubjub scalar can
    // carry one digit past the scalar's bit length, derived here from the
    // real modulus rather than the constant it must match.
    assert_eq!(bit_length(jubjub_modulus_minus_one), JUBJUB_SCALAR_BITS);
    let effective_width =
        FIXED_BASE_SIGNED_DIGIT_ROUNDS - FIXED_BASE_LEADING_ZERO_ROUNDS;
    assert!(
        effective_width >= bit_length(jubjub_modulus_minus_one) + 1,
        "the effective width must fit every canonical scalar's NAF",
    );
}
