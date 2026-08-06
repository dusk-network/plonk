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
//! The digit forgeries compile the verifier key from the honest production
//! gadget, then use the production constraint emitter with attacker-chosen
//! digits. The forged circuits therefore have exactly the same selectors and
//! wiring as the honest circuit. The injected assignments satisfy the old
//! fixed-base transitions, the closing field equality, and the claimed public
//! point; only the new canonical-scalar or leading-zero constraint rejects
//! them. One test builds no circuit: it pins the width bound those constraints
//! rely on to the field moduli by exact integer arithmetic.
//!
//! The digits are one axis a prover is free on; the widget's helper wire is
//! another, independent of it. To keep its round formula below degree 4 the
//! widget allocates a per-row witness for `x_alpha * y_alpha`, and its identity
//! folds four residuals as `bit_consistency + κ·xy_alpha + κ²·x3 + κ³·y3`. The
//! `κ` term is that wire's only in-gate pin; the other two are the accumulator
//! checks, which consume the wire in place of the product. Each of those is
//! linear in its own output coordinate, so at any wire value they solve for a
//! matching accumulator — one that nothing constrains to the curve. A prover
//! who forges the wire and carries the forced accumulator into the next round
//! therefore satisfies every other residual, the bit consistency, the closing
//! field equality, the leading-zero bound and the canonicality guard alike, and
//! claims a public multiple of the attacker's choosing. `forced_accumulator`
//! does that solving, so it is itself pinned against the widget's own
//! identity — at every round of every forged chain, and at all three places
//! the widget computes it: the prover's quotient, the prover's linearization
//! and the verifier key's linearization commitment. That pin is this module's
//! only reach into `proof_system::widget`, and building both widget keys by
//! struct literal makes a new field on either break the build here rather than
//! silently weaken the pin.

use alloc::format;
use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{EDWARDS_D, JubJubAffine, JubJubExtended, JubJubScalar};
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{
    assert_rejected, assert_verifies, gate_digest, invert, steering_target,
};
use crate::commitment_scheme::Commitment;
use crate::composer::fixed_base::{
    FIXED_BASE_LEADING_ZERO_ROUNDS, FIXED_BASE_MAX_SOUND_WIDTH,
    FIXED_BASE_SIGNED_DIGIT_ROUNDS, JUBJUB_SCALAR_BITS,
};
use crate::composer::{Composer, Constraint, Witness, WitnessPoint};
use crate::error::Error;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::prelude::{
    Circuit, Compiler, PlonkVersion, Prover, PublicParameters, Verifier,
};
use crate::proof_system::linearization_poly::ProofEvaluations;
use crate::proof_system::widget::ecc::scalar_mul;

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

/// The axis a forged circuit cheats on. Both emit the honest gate layout —
/// [`assert_rejected`] requires it — and differ only in the witnesses they fill
/// it with.
#[derive(Clone)]
enum Forgery {
    /// Attacker-chosen signed digits, with every witness the production
    /// emitter derives from them left honest.
    Digits(Box<[i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS]>),
    /// Honest signed digits, with one round's helper wire falsified and the
    /// point accumulators the widget's own output checks then force.
    HelperWire(ForcedChain),
}

#[derive(Clone)]
struct FixedBaseCircuit {
    scalar: BlsScalar,
    claimed_point: JubJubExtended,
    forgery: Option<Forgery>,
}

impl Default for FixedBaseCircuit {
    fn default() -> Self {
        Self {
            scalar: BlsScalar::zero(),
            claimed_point: JubJubExtended::identity(),
            forgery: None,
        }
    }
}

impl FixedBaseCircuit {
    fn honest(scalar: JubJubScalar) -> Self {
        Self {
            scalar: BlsScalar::from(scalar),
            claimed_point: dusk_jubjub::GENERATOR_EXTENDED * scalar,
            forgery: None,
        }
    }

    fn forged(
        scalar: BlsScalar,
        digits: [i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
    ) -> Self {
        Self {
            scalar,
            claimed_point: point_from_signed_digits(&digits),
            forgery: Some(Forgery::Digits(Box::new(digits))),
        }
    }

    /// Honest digits, `wire` replacing one round's helper wire, and the public
    /// multiple claimed to be whatever the accumulator checks then force. That
    /// multiple is off-curve in general — nothing in the widget constrains the
    /// accumulator to the curve, so the binding term is the whole of the
    /// defence.
    fn forged_helper_wire(
        digits: &[i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
        wire: ForgedWire,
    ) -> Self {
        let chain = ForcedChain::new(digits, Some(wire));
        let (x, y) = chain.endpoint();

        Self {
            scalar: signed_digit_endpoint(digits),
            claimed_point: JubJubAffine::from_raw_unchecked(x, y).into(),
            forgery: Some(Forgery::HelperWire(chain)),
        }
    }
}

impl Circuit for FixedBaseCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let scalar = composer.append_public(self.scalar);
        let point = match &self.forgery {
            None => composer
                .component_mul_generator(
                    scalar,
                    dusk_jubjub::GENERATOR_EXTENDED,
                )?
                .into(),
            Some(Forgery::Digits(digits)) => composer
                .append_fixed_base_signed_digits(
                    scalar,
                    dusk_jubjub::GENERATOR_EXTENDED,
                    digits,
                )?,
            Some(Forgery::HelperWire(chain)) => {
                forge_fixed_base_rounds(composer, scalar, chain)
            }
        };
        composer.assert_equal_public_point(point, self.claimed_point)?;
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

// ---------------------------------------------------------------------------
// Helper-wire binding.
// ---------------------------------------------------------------------------

/// The fixed multiples the widget reads from its `q_l`/`q_r`/`q_c` selectors,
/// `[2^(255 - round)]G` at `round` — `append_fixed_base_signed_digits`' table,
/// built and reversed the same way so the two orderings cannot disagree.
fn round_multiples() -> Vec<JubJubAffine> {
    let mut multiples =
        vec![JubJubExtended::default(); FIXED_BASE_SIGNED_DIGIT_ROUNDS];
    multiples[0] = dusk_jubjub::GENERATOR_EXTENDED;
    for i in 1..FIXED_BASE_SIGNED_DIGIT_ROUNDS {
        multiples[i] = multiples[i - 1].double();
    }

    let mut multiples: Vec<_> =
        dusk_jubjub::batch_normalize(&mut multiples).collect();
    multiples.reverse();
    multiples
}

/// The accumulator the widget's two output checks force at a round, given the
/// accumulator entering it and the value on its helper wire. Each check is
/// linear in its own output coordinate, so each has exactly one solution:
///
///   `x_3 * (1 + D*xy_alpha*acc_x*acc_y) = acc_x*y_alpha + acc_y*x_alpha`
///   `y_3 * (1 - D*xy_alpha*acc_x*acc_y) = acc_y*y_alpha + acc_x*x_alpha`
///
/// `compute_quotient_i` weights these by `κ²`/`κ³`; a factor on a residual that
/// must vanish outright changes nothing. Pinned against the widget in
/// [`forced_accumulators_satisfy_the_widget_output_checks`].
///
/// At the two wire values `±1/(D*acc_x*acc_y)` one of the denominators
/// vanishes: that check degenerates and leaves its coordinate free. Inverting
/// both means such a wire panics here rather than being silently constructed,
/// so no case below can reach one without saying so.
fn forced_accumulator(
    acc: (BlsScalar, BlsScalar),
    bit: BlsScalar,
    beta: (BlsScalar, BlsScalar),
    xy_alpha: BlsScalar,
) -> (BlsScalar, BlsScalar) {
    let (acc_x, acc_y) = acc;
    let (x_alpha, y_alpha) = alpha(bit, beta);
    let skew = EDWARDS_D * xy_alpha * acc_x * acc_y;

    (
        (acc_x * y_alpha + acc_y * x_alpha) * invert(BlsScalar::one() + skew),
        (acc_y * y_alpha + acc_x * x_alpha) * invert(BlsScalar::one() - skew),
    )
}

/// The point the round adds, `[bit]·beta`, as the widget derives it from the
/// extracted bit and its `q_l`/`q_r` selectors rather than from a witness.
fn alpha(
    bit: BlsScalar,
    (x_beta, y_beta): (BlsScalar, BlsScalar),
) -> (BlsScalar, BlsScalar) {
    (
        bit * x_beta,
        bit.square() * (y_beta - BlsScalar::one()) + BlsScalar::one(),
    )
}

/// One round of the fixed-base widget as the forgery drives it.
#[derive(Clone, Copy)]
struct Round {
    /// The signed digit the round's shifted `d` wire encodes as `d_w - 2*d`.
    bit: BlsScalar,
    /// The round's fixed multiple `[2^(255 - round)]G`.
    beta: (BlsScalar, BlsScalar),
    /// The value on the helper wire: `bit * x_beta * y_beta` when honest.
    xy_alpha: BlsScalar,
    /// The point accumulator entering the round.
    acc: (BlsScalar, BlsScalar),
    /// The accumulator the round's two output checks force on the way out, and
    /// so the one entering the next round.
    forced: (BlsScalar, BlsScalar),
}

impl Round {
    /// The wire value the round's binding term demands, `bit * q_c`.
    fn honest_wire(&self) -> BlsScalar {
        self.bit * self.beta.0 * self.beta.1
    }
}

/// The round a forgery falsifies and the value it puts on that round's helper
/// wire.
#[derive(Clone, Copy)]
struct ForgedWire {
    round: usize,
    xy_alpha: BlsScalar,
}

/// The whole witness assignment the widget's own checks force for a digit
/// sequence, once an optional forged wire is substituted. With no forgery this
/// is the honest assignment, which
/// [`fixed_base_binds_the_helper_wire`] requires to walk the real curve.
#[derive(Clone)]
struct ForcedChain {
    rounds: Vec<Round>,
    /// The scalar accumulator, one entry per round plus the closing state. The
    /// forgeries leave it honest, so the closing field equality, the
    /// leading-zero bound and the canonicality guard all still pass.
    scalars: Vec<BlsScalar>,
}

impl ForcedChain {
    fn new(
        digits: &[i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
        forged: Option<ForgedWire>,
    ) -> Self {
        let multiples = round_multiples();
        let mut rounds = Vec::with_capacity(FIXED_BASE_SIGNED_DIGIT_ROUNDS);
        let mut scalars = vec![BlsScalar::zero()];
        let mut acc = (BlsScalar::zero(), BlsScalar::one());

        // The widget consumes the digits most-significant first, against a
        // multiples table reversed to match.
        for (round, digit) in digits.iter().rev().enumerate() {
            let bit = digit_to_scalar(*digit);
            let beta = (multiples[round].get_u(), multiples[round].get_v());

            let xy_alpha = match forged {
                Some(wire) if wire.round == round => wire.xy_alpha,
                _ => bit * beta.0 * beta.1,
            };

            let forced = forced_accumulator(acc, bit, beta, xy_alpha);
            rounds.push(Round {
                bit,
                beta,
                xy_alpha,
                acc,
                forced,
            });
            acc = forced;

            let previous = *scalars.last().expect("the vector is nonempty");
            scalars.push(previous.double() + bit);
        }

        Self { rounds, scalars }
    }

    /// The accumulator the last round forces, which the widget returns as the
    /// claimed multiple.
    fn endpoint(&self) -> (BlsScalar, BlsScalar) {
        self.rounds[LAST_ROUND].forced
    }
}

/// An attacker's fork of `Composer::append_fixed_base_signed_digits`: the same
/// gates in the same order with the same wiring, differing only in the values
/// it assigns to the point accumulators and the helper wires.
/// [`assert_rejected`] compares the layout this emits against the production
/// gadget's, and [`component_mul_generator_layout_matches_golden`] pins that
/// layout in turn — so neither can drift alone.
fn forge_fixed_base_rounds(
    composer: &mut Composer,
    jubjub: Witness,
    chain: &ForcedChain,
) -> WitnessPoint {
    // The canonicality guard is not what the forgery cheats on, so it is called
    // rather than copied: its gates come first in the production emitter and
    // have to land in the same place here.
    composer.assert_canonical_jubjub_scalar(jubjub);

    let mut leading_accumulator = Composer::ZERO;

    for (index, round) in chain.rounds.iter().enumerate() {
        let acc_x = composer.append_witness(round.acc.0);
        let acc_y = composer.append_witness(round.acc.1);
        let accumulated_bit = composer.append_witness(chain.scalars[index]);

        if index == FIXED_BASE_LEADING_ZERO_ROUNDS {
            leading_accumulator = accumulated_bit;
        }

        if index == 0 {
            composer.assert_equal_constant(acc_x, BlsScalar::zero(), None);
            composer.assert_equal_constant(acc_y, BlsScalar::one(), None);
            composer.assert_equal_constant(
                accumulated_bit,
                BlsScalar::zero(),
                None,
            );
        }

        let (x_beta, y_beta) = round.beta;
        let xy_alpha = composer.append_witness(round.xy_alpha);

        let constraint = Constraint::group_add_fixed_base(&Constraint::new())
            .left(x_beta)
            .right(y_beta)
            .constant(x_beta * y_beta)
            .a(acc_x)
            .b(acc_y)
            .c(xy_alpha)
            .d(accumulated_bit);

        composer.append_custom_gate(constraint);
    }

    let (x, y) = chain.endpoint();
    let acc_x = composer.append_witness(x);
    let acc_y = composer.append_witness(y);
    let last_accumulated_bit =
        composer.append_witness(chain.scalars[FIXED_BASE_SIGNED_DIGIT_ROUNDS]);

    composer.append_gate(
        Constraint::new().a(acc_x).b(acc_y).d(last_accumulated_bit),
    );

    composer.assert_equal_constant(
        leading_accumulator,
        BlsScalar::zero(),
        None,
    );
    composer.assert_equal(last_accumulated_bit, jubjub);

    WitnessPoint::new(acc_x, acc_y)
}

/// The last signed-digit round. Its forced accumulator is the widget's output,
/// so a wire forged here steers the publicly claimed multiple directly.
const LAST_ROUND: usize = FIXED_BASE_SIGNED_DIGIT_ROUNDS - 1;

/// A round in the middle of the chain: the accumulator a forgery there forces
/// is carried through every remaining round before it reaches the output.
/// Derived rather than written out, so it cannot drift past [`LAST_ROUND`] or
/// back into the leading-zero block if the round count ever moves.
const MID_CHAIN_ROUND: usize = FIXED_BASE_SIGNED_DIGIT_ROUNDS / 2;

/// The scalars the helper-wire forgeries multiply the generator by. Both are
/// canonical and full width, so the accumulator is a nonidentity point well
/// before [`MID_CHAIN_ROUND`], and both are odd, so the last round's digit —
/// and with it the honest value of the wire forged there — is nonzero. The
/// forgery cases assert both properties rather than trusting this note.
///
/// They differ in digit density, which is what decides how many rounds carry a
/// zero digit. `r - 2`'s width-2 NAF is dense; `2^251 + 1`'s is zero
/// everywhere between its two set bits, so its mid-chain forgery lands on a
/// round where `bit = 0` and drives the branch of [`alpha`] that the dense
/// scalar never reaches there — a round the widget must still solve, since the
/// forged wire keeps the skew term alive even where the digit adds nothing.
fn helper_wire_scalars() -> [(&'static str, JubJubScalar); 2] {
    [
        ("r - 2", -JubJubScalar::from(2u64)),
        // 251 = 3 * 64 + 59, so the top bit lands in the last limb.
        ("2^251 + 1", JubJubScalar::from_raw([1, 0, 0, 1 << 59])),
    ]
}

/// The helper-wire value whose forced x-coordinate at `round` is `x_3`: that
/// round's x check solved for the wire instead of the coordinate. This is what
/// turns a free choice of the wire into a free choice of a coordinate.
fn wire_forcing_x3(
    honest: &ForcedChain,
    round: usize,
    x_3: BlsScalar,
) -> BlsScalar {
    let Round { bit, beta, acc, .. } = honest.rounds[round];
    let (acc_x, acc_y) = acc;
    let (x_alpha, y_alpha) = alpha(bit, beta);
    let numerator = acc_x * y_alpha + acc_y * x_alpha;

    (numerator - x_3) * invert(x_3 * EDWARDS_D * acc_x * acc_y)
}

/// The forged wires, shared so the circuit-level forgeries and the widget-level
/// pin cannot drift apart.
fn forged_wires(honest: &ForcedChain) -> [(&'static str, ForgedWire); 4] {
    let off_by_one = |round: usize| ForgedWire {
        round,
        xy_alpha: honest.rounds[round].honest_wire() + BlsScalar::one(),
    };

    [
        (
            "mid-chain helper wire off by one",
            off_by_one(MID_CHAIN_ROUND),
        ),
        ("last-round helper wire off by one", off_by_one(LAST_ROUND)),
        (
            "last-round helper wire zeroed",
            ForgedWire {
                round: LAST_ROUND,
                xy_alpha: BlsScalar::zero(),
            },
        ),
        (
            "last-round helper wire steering the claimed multiple's \
             x-coordinate",
            ForgedWire {
                round: LAST_ROUND,
                xy_alpha: wire_forcing_x3(
                    honest,
                    LAST_ROUND,
                    steering_target().get_u(),
                ),
            },
        ),
    ]
}

#[test]
fn fixed_base_binds_the_helper_wire() {
    assert_eq!(PlonkVersion::current(), PlonkVersion::V3);

    let mut rng = StdRng::seed_from_u64(0xa19a_501d);
    let pp = PublicParameters::setup(1 << 10, &mut rng).expect("setup");
    let (prover, verifier) = compile(&pp);

    // The two scalars have to differ where their note claims they do —
    // otherwise the second buys a repeat of the first rather than the `bit = 0`
    // mid-chain round the dense one never reaches.
    let mid_chain_digits = helper_wire_scalars().map(|(_, scalar)| {
        ForcedChain::new(&scalar.compute_windowed_naf(2), None).rounds
            [MID_CHAIN_ROUND]
            .bit
    });
    assert!(
        mid_chain_digits.contains(&BlsScalar::zero())
            && mid_chain_digits.iter().any(|bit| *bit != BlsScalar::zero()),
        "the scalars must differ in whether the mid-chain round carries a \
         digit",
    );

    // The gate layout does not depend on the scalar, so one compiled key
    // serves every case below.
    for (label, scalar) in helper_wire_scalars() {
        let digits = scalar.compute_windowed_naf(2);
        let honest = FixedBaseCircuit::honest(scalar);

        // More than a sanity control. Every forgery below is turned away at
        // proving time, so none of them reaches a verifier, and the
        // widget-level pin evaluates the identity on a synthetic
        // one-row key rather than in the proving path. This round-trip
        // is what exercises the real one: the verifier folds
        // `-Z_H(z)·[t]` in beside the widget's linearization
        // commitment, so the quotient, the prover's linearization and the
        // verifier key's must agree at a random `z` or this line fails.
        // Retarget it at a circuit without fixed-base rows and that
        // agreement stops being checked.
        assert_verifies(&prover, &verifier, &mut rng, &honest);

        let chain = ForcedChain::new(&digits, None);
        let honest_point = JubJubAffine::from(honest.claimed_point);

        // Solving the widget's output checks round by round on the honest wires
        // must walk the real curve and land on the true multiple — what ties
        // `forced_accumulator` to `dusk-jubjub`'s own arithmetic, and the
        // digits to the scalar the circuit exposes.
        assert_eq!(
            signed_digit_endpoint(&digits),
            BlsScalar::from(scalar),
            "{label}: the digits must encode the scalar the circuit exposes",
        );
        assert_eq!(
            point_from_signed_digits(&digits),
            honest.claimed_point,
            "{label}: the digits must encode the true multiple",
        );
        assert_eq!(
            chain.endpoint(),
            (honest_point.get_u(), honest_point.get_v()),
            "{label}: solving the output checks on the honest wires must give the \
         true multiple",
        );

        // Both forged rounds need a nonzero accumulator: the wire reaches the
        // output checks only through `D*xy_alpha*acc_x*acc_y`, so at the
        // identity accumulator a forged wire would leave the forced
        // coordinates untouched and the forgery would claim the honest
        // point. This is what the scalars' "full width" has to buy,
        // asserted rather than assumed.
        for round in [MID_CHAIN_ROUND, LAST_ROUND] {
            let (acc_x, acc_y) = chain.rounds[round].acc;
            assert_ne!(
                acc_x,
                BlsScalar::zero(),
                "{label} round {round}: acc_x is zero",
            );
            assert_ne!(
                acc_y,
                BlsScalar::zero(),
                "{label} round {round}: acc_y is zero",
            );
        }

        // And the last round's digit has to be nonzero, or its honest wire is
        // already zero and the "zeroed" case forges nothing. This is what the
        // scalars' oddness has to buy.
        assert_ne!(
            chain.rounds[LAST_ROUND].bit,
            BlsScalar::zero(),
            "{label}: the last round's digit must be nonzero",
        );

        let [mid_chain, off_by_one, zeroed, steering] = forged_wires(&chain);

        // The reach of the attack: round-tripping the steering wire back
        // through the chain must aim the publicly claimed multiple at
        // the target. Only the x-coordinate is steerable — one wire
        // against two checks — and the y-coordinate the y check then
        // forces is nothing the widget objects to.
        let target = steering_target();
        assert_ne!(target.get_u(), honest_point.get_u(), "{label}");
        assert_eq!(
            ForcedChain::new(&digits, Some(steering.1)).endpoint().0,
            target.get_u(),
            "{label}: the steering wire must aim the claimed multiple at the \
         target",
        );

        for (case, wire) in [mid_chain, off_by_one, zeroed, steering] {
            let case = format!("{label}: {case}");
            let round = &chain.rounds[wire.round];
            assert_eq!(
                round.xy_alpha,
                round.honest_wire(),
                "{case}: the reference chain must carry the honest wire",
            );
            assert_ne!(
                wire.xy_alpha, round.xy_alpha,
                "{case}: must forge the wire",
            );

            let forgery = FixedBaseCircuit::forged_helper_wire(&digits, wire);
            assert_eq!(
                forgery.scalar, honest.scalar,
                "{case}: the public scalar must stay honest, so the closing \
             equality is not what rejects",
            );
            assert_ne!(
                forgery.claimed_point, honest.claimed_point,
                "{case}: the forged wire must move the claimed multiple",
            );

            assert_rejected(&prover, &mut rng, &honest, &forgery, &case);
        }
    }
}

/// The forgeries rest on `forced_accumulator`'s coordinates satisfying the
/// widget's own checks at every round they drive; nothing else here asserts
/// that. The honest-witness comparison in
/// [`fixed_base_binds_the_helper_wire`] pins one point of it, which an algebra
/// change that still accepted the true Edwards sum would survive. This covers
/// the forged wires, and it covers whole chains rather than the forged round
/// alone: past a mid-chain forgery every later round takes an off-curve
/// accumulator in, and if `forced_accumulator` did not solve the residuals
/// there too, those rounds would be unsatisfied and would reject the forgery
/// in the binding term's place.
///
/// A single-`1` selector evaluation reduces `compute_quotient_i` to the
/// identity times the challenge, so matching the binding residual says `κ²·x3 +
/// κ³·y3` vanishes — one equation in two unknowns, which a matched nonzero pair
/// also satisfies. Two challenges with distinct nonzero squares force both to
/// zero.
///
/// That equality would also hold for a widget with both accumulator checks
/// deleted, the identity then being the binding term outright, so each
/// coordinate is perturbed and required to move the identity off it.
///
/// The identity is computed in three places: the prover's quotient, the
/// prover's linearization, and the verifier's linearization commitment. All
/// three are pinned. The honest control in
/// [`fixed_base_binds_the_helper_wire`] already fails if they disagree — a
/// proof only verifies while they do, so no weakening can hide in one or two
/// of them — but that leaves the coverage incidental, and the copy a forgery
/// is actually turned away by is the quotient's. Asserting all three carry the
/// same binding term says it outright.
#[test]
fn forced_accumulators_satisfy_the_widget_output_checks() {
    let evaluation = |value: BlsScalar| {
        Evaluations::from_vec_and_domain(
            Vec::from([value]),
            EvaluationDomain::new(1).expect("a one-element domain"),
        )
    };
    let constant = |value: BlsScalar| {
        Polynomial::from_coefficients_vec(Vec::from([value]))
    };

    // Arbitrary, beyond being nonzero with differing squares, so the two
    // equations they give in the accumulator residuals are independent.
    let challenges = [
        BlsScalar::from(0xa19a_0117u64),
        BlsScalar::from(0x7b0f_fd83u64),
    ];
    assert_ne!(challenges[0], BlsScalar::zero());
    assert_ne!(challenges[1], BlsScalar::zero());
    assert_ne!(
        challenges[0].square(),
        challenges[1].square(),
        "the two challenges must weight the accumulator residuals differently",
    );

    for (label, scalar) in helper_wire_scalars() {
        let digits = scalar.compute_windowed_naf(2);
        let honest = ForcedChain::new(&digits, None);

        let cases =
            forged_wires(&honest).map(|(case, wire)| (case, Some(wire)));
        for (case, forged) in [("honest wires", None)].into_iter().chain(cases)
        {
            let case = format!("{label}: {case}");
            let chain = ForcedChain::new(&digits, forged);

            for (round, state) in chain.rounds.iter().enumerate() {
                let Round {
                    beta,
                    xy_alpha,
                    acc,
                    forced,
                    ..
                } = *state;

                // The widget reads the round's constants from its selectors, so
                // they enter as evaluations rather than as witnesses. A
                // single-`1` `q_fixed_group_add` leaves the
                // identity itself.
                let prover_key = scalar_mul::fixed_base::ProverKey {
                    q_l: (constant(beta.0), evaluation(beta.0)),
                    q_r: (constant(beta.1), evaluation(beta.1)),
                    q_c: (
                        constant(beta.0 * beta.1),
                        evaluation(beta.0 * beta.1),
                    ),
                    q_fixed_group_add: (
                        constant(BlsScalar::one()),
                        evaluation(BlsScalar::one()),
                    ),
                };
                let verifier_key = scalar_mul::fixed_base::VerifierKey {
                    q_l: Commitment::default(),
                    q_r: Commitment::default(),
                    q_fixed_group_add: Commitment::default(),
                };

                for challenge in challenges {
                    let binding_term = (state.honest_wire() - xy_alpha)
                        * challenge.square()
                        * challenge;

                    let quotient = |x_3, y_3| {
                        prover_key.compute_quotient_i(
                            0,
                            &challenge,
                            &acc.0,
                            &x_3,
                            &acc.1,
                            &y_3,
                            &xy_alpha,
                            &chain.scalars[round],
                            &chain.scalars[round + 1],
                        )
                    };

                    assert_eq!(
                        quotient(forced.0, forced.1),
                        binding_term,
                        "{case} round {round}: the widget's identity must reduce \
                     to the binding term",
                    );

                    // Each check carries a nonzero coefficient on its own
                    // coordinate (`1 ± skew` — nonzero here, or
                    // `forced_accumulator` would have panicked), so moving that
                    // coordinate must move the identity. Deleting both checks
                    // fails here, not above.
                    assert_ne!(
                        quotient(forced.0 + BlsScalar::one(), forced.1),
                        binding_term,
                        "{case} round {round}: the x_3 check must constrain x_3",
                    );
                    assert_ne!(
                        quotient(forced.0, forced.1 + BlsScalar::one()),
                        binding_term,
                        "{case} round {round}: the y_3 check must constrain y_3",
                    );

                    // The same round, as the two linearizations see it. Only
                    // the fields the fixed-base widget
                    // reads carry values; the rest
                    // belong to other widgets and are left at their default.
                    let evaluations = ProofEvaluations {
                        a_eval: acc.0,
                        a_w_eval: forced.0,
                        b_eval: acc.1,
                        b_w_eval: forced.1,
                        c_eval: xy_alpha,
                        d_eval: chain.scalars[round],
                        d_w_eval: chain.scalars[round + 1],
                        q_c_eval: beta.0 * beta.1,
                        q_l_eval: beta.0,
                        q_r_eval: beta.1,
                        ..Default::default()
                    };

                    assert_eq!(
                        prover_key
                            .compute_linearization(&challenge, &evaluations),
                        constant(binding_term),
                        "{case} round {round}: the prover's linearization must \
                     carry the same binding term",
                    );

                    let mut scalars = Vec::new();
                    let mut points = Vec::new();
                    verifier_key.compute_linearization_commitment(
                        &challenge,
                        &mut scalars,
                        &mut points,
                        &evaluations,
                    );
                    assert_eq!(
                        scalars,
                        Vec::from([binding_term]),
                        "{case} round {round}: the verifier's linearization must \
                     carry the same binding term",
                    );
                }
            }
        }
    }
}

/// `assert_rejected` only checks the hand-copied emission against the gadget —
/// an edit to both stays green. This pins the layout on its own, so the fork
/// and the gadget cannot drift together. The layout is the same for every
/// scalar: nothing in the emission branches on a witness value.
///
/// It does not yet stand for any shipped verifier key: the signed-digit and
/// canonicality bounds it includes are unreleased, and they already changed
/// the key of every caller. Until the release that ships them it is a drift
/// pin only, and becomes a compatibility pin then. The soundness suite's other
/// goldens are a mix of the two — which one a golden is depends on whether the
/// gadget it was captured from has shipped, so read each one's own note rather
/// than assuming.
#[test]
fn component_mul_generator_layout_matches_golden() {
    // `gate_digest` captured from `component_mul_generator` as it stands with
    // the unreleased signed-digit and canonicality bounds.
    const GOLDEN: [u8; 32] = [
        12, 248, 174, 80, 4, 183, 76, 71, 51, 243, 231, 56, 142, 43, 223, 49,
        71, 66, 186, 118, 187, 39, 149, 99, 2, 10, 183, 18, 145, 85, 227, 83,
    ];

    let mut composer = Composer::initialized();
    let (_, scalar) = helper_wire_scalars()[0];
    let scalar = composer.append_witness(BlsScalar::from(scalar));
    composer
        .component_mul_generator(scalar, dusk_jubjub::GENERATOR_EXTENDED)
        .expect("honest fixed-base multiplication");

    assert_eq!(
        gate_digest(&composer.constraints),
        GOLDEN,
        "component_mul_generator's gate layout drifted from the pinned one",
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
