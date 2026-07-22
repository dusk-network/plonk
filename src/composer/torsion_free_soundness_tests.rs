// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regressions for `assert_torsion_free_point`.
//!
//! The gadget must admit exactly the prime-order subgroup: honest members
//! (identity included) prove, while on-curve torsion components and off-curve
//! points are rejected. The threat model is a prover free to assign *every*
//! witness, not just the input point — so beyond the production entry point
//! (which derives the honest `Q`) the forgeries here inject attacker-chosen
//! `Q` values and forge each family of intermediate witnesses directly: the
//! on-curve row's squares and the doubling chain's outputs.

use dusk_jubjub::GENERATOR_EXTENDED;
use ff::Field;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::soundness_support::{assert_rejected, assert_verifies, gate_digest};
use super::*;
use crate::prelude::{Compiler, Prover, PublicParameters, Verifier};

// Torsion points of the embedded curve, raw coordinates from dusk-jubjub's
// (private) EIGHT_TORSION table. Their claimed orders are pinned by
// `subgroup_parameters_hold`.
fn torsion_order_8() -> JubJubAffine {
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0xd92e_6a79_2720_0d43,
            0x7aa4_1ac4_3dae_8582,
            0xeaaa_e086_a166_18d1,
            0x71d4_df38_ba9e_7973,
        ]),
        BlsScalar::from_raw([
            0xff0d_2068_eff4_96dd,
            0x9106_ee90_f384_a4a1,
            0x16a1_3035_ad4d_7266,
            0x4958_bdb2_1966_982e,
        ]),
    )
}

fn torsion_order_4() -> JubJubAffine {
    JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0xfffe_ffff_0000_0001,
            0x67ba_a400_89fb_5bfe,
            0xa5e8_0b39_939e_d334,
            0x73ed_a753_299d_7d47,
        ]),
        BlsScalar::zero(),
    )
}

fn torsion_order_2() -> JubJubAffine {
    JubJubAffine::from_raw_unchecked(BlsScalar::zero(), -BlsScalar::one())
}

/// An off-curve point: `(0, 0)` does not satisfy the curve equation.
fn off_curve_zero() -> JubJubAffine {
    JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::zero())
}

/// An arbitrary member of the prime-order subgroup.
fn prime_order_point() -> JubJubAffine {
    (GENERATOR_EXTENDED * JubJubScalar::from(0xdead_beef_u64)).into()
}

/// How the circuit drives the gadget: the production entry point, or one of
/// three forging provers that emit the exact same gate layout with witnesses
/// of their own choosing.
enum Mode {
    /// Production entry point; the honest `Q` is derived internally.
    Honest,
    /// A prover injecting an arbitrary `Q` while assigning the remaining
    /// intermediates honestly — its best strategy, since every witness
    /// downstream of `Q` is forced by an honestly-satisfiable gate.
    InjectQ(JubJubAffine),
    /// A prover that additionally forges the on-curve row's intermediates
    /// `(u², v², u²·v²)`, satisfying the curve-equation gate for an off-curve
    /// `Q` — it must then be caught by the multiplication gates binding those
    /// intermediates to `Q`'s coordinates.
    ForgeOnCurveRow {
        q: JubJubAffine,
        u2: BlsScalar,
        v2: BlsScalar,
        u2v2: BlsScalar,
    },
    /// A prover that forges the first doubling's output witnesses to jump
    /// the chain to an attacker-chosen point `s` whose remaining (honest)
    /// doublings land exactly on the input — every other gate is satisfied,
    /// so only the `q_variable_group_add` widget identity binding the
    /// doubling's output can reject it.
    ForgeFirstDoubling { q: JubJubAffine, s: JubJubAffine },
}

struct TorsionFreeCircuit {
    point: JubJubAffine,
    mode: Mode,
}

impl TorsionFreeCircuit {
    fn honest(point: JubJubAffine) -> Self {
        Self {
            point,
            mode: Mode::Honest,
        }
    }

    fn inject_q(point: JubJubAffine, q: JubJubAffine) -> Self {
        Self {
            point,
            mode: Mode::InjectQ(q),
        }
    }
}

impl Default for TorsionFreeCircuit {
    fn default() -> Self {
        Self::honest(JubJubAffine::identity())
    }
}

/// Emit the exact gate `gate_mul` emits for `a · b`, but with the output
/// witness assigned an attacker-chosen `value` instead of the product.
fn forged_mul(
    composer: &mut Composer,
    a: Witness,
    b: Witness,
    value: BlsScalar,
) -> Witness {
    let c = composer.append_witness(value);
    composer.append_gate(
        Constraint::new()
            .mult(1)
            .output(-BlsScalar::one())
            .a(a)
            .b(b)
            .c(c),
    );
    c
}

/// Emit the exact gates `component_add_point(q, q)` emits, but with the
/// output witnesses assigned the attacker-chosen point `s` instead of the
/// doubling's result. The `x_1 · y_2` helper witness stays honest to isolate
/// the output binding.
fn forged_double(
    composer: &mut Composer,
    q: WitnessPoint,
    s: JubJubAffine,
) -> WitnessPoint {
    let qu = *q.x();
    let qv = *q.y();

    let x1y2 = composer.append_witness(composer[qu] * composer[qv]);
    let x3 = composer.append_witness(s.get_u());
    let y3 = composer.append_witness(s.get_v());

    let constraint = Constraint::new().a(qu).b(qv).c(qu).d(qv);
    let constraint = Constraint::group_add_variable_base(&constraint);
    composer.append_custom_gate(constraint);

    let constraint = Constraint::new().a(x3).b(y3).d(x1y2);
    composer.append_custom_gate(constraint);

    WitnessPoint::new(x3, y3)
}

/// The honest on-curve row of `assert_torsion_free_gates`, emitted verbatim
/// so the doubling-chain forgery keeps every other gate honestly satisfied.
fn honest_on_curve_row(composer: &mut Composer, q: WitnessPoint) {
    let qu = *q.x();
    let qv = *q.y();
    let u2 = composer.gate_mul(Constraint::new().mult(1).a(qu).b(qu));
    let v2 = composer.gate_mul(Constraint::new().mult(1).a(qv).b(qv));
    let u2v2 = composer.gate_mul(Constraint::new().mult(1).a(u2).b(v2));
    composer.append_gate(
        Constraint::new()
            .left(-BlsScalar::one())
            .a(u2)
            .right(1)
            .b(v2)
            .output(-EDWARDS_D)
            .c(u2v2)
            .constant(-BlsScalar::one()),
    );
}

impl Circuit for TorsionFreeCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let point = composer.append_point(self.point);
        match &self.mode {
            Mode::Honest => composer.assert_torsion_free_point(point),
            Mode::InjectQ(q) => composer.assert_torsion_free_gates(point, *q),
            Mode::ForgeOnCurveRow { q, u2, v2, u2v2 } => {
                // Mirror `assert_torsion_free_gates` gate for gate, with the
                // three `gate_mul` outputs replaced by attacker witnesses.
                // `assert_rejected` pins this mirror to the production layout.
                let q = composer.append_point(*q);
                let qu = *q.x();
                let qv = *q.y();
                let u2 = forged_mul(composer, qu, qu, *u2);
                let v2 = forged_mul(composer, qv, qv, *v2);
                let u2v2 = forged_mul(composer, u2, v2, *u2v2);
                composer.append_gate(
                    Constraint::new()
                        .left(-BlsScalar::one())
                        .a(u2)
                        .right(1)
                        .b(v2)
                        .output(-EDWARDS_D)
                        .c(u2v2)
                        .constant(-BlsScalar::one()),
                );
                let q2 = composer.component_add_point(q, q);
                let q4 = composer.component_add_point(q2, q2);
                let q8 = composer.component_add_point(q4, q4);
                composer.assert_equal_point(point, q8);
            }
            Mode::ForgeFirstDoubling { q, s } => {
                // Mirror `assert_torsion_free_gates` with only the first
                // doubling's output witnesses forged to `s`; the remaining
                // doublings run honestly from the forged point.
                let q = composer.append_point(*q);
                honest_on_curve_row(composer, q);
                let q2 = forged_double(composer, q, *s);
                let q4 = composer.component_add_point(q2, q2);
                let q8 = composer.component_add_point(q4, q4);
                composer.assert_equal_point(point, q8);
            }
        }
        Ok(())
    }
}

fn setup() -> (Prover, Verifier, StdRng) {
    let mut rng = StdRng::seed_from_u64(0x8_04d3);
    let pp = PublicParameters::setup(1 << 8, &mut rng).expect("setup");
    let (prover, verifier) =
        Compiler::compile::<TorsionFreeCircuit>(&pp, b"torsion-free")
            .expect("compile");
    (prover, verifier, rng)
}

// The facts the gadget's soundness argument leans on: the cofactor inverse
// really inverts 8, the addition law is complete (`a = -1` a square, `d` a
// non-square, so the doubling chain has no exceptional case with a free
// witness), and the torsion fixtures have the orders their names claim.
#[test]
fn subgroup_parameters_hold() {
    assert_eq!(EIGHT_INV * JubJubScalar::from(8u64), JubJubScalar::one());

    assert!(
        bool::from((-BlsScalar::one()).sqrt().is_some()),
        "a = -1 must be a square"
    );
    assert!(
        bool::from(EDWARDS_D.sqrt().is_none()),
        "d must be a non-square"
    );

    let identity = JubJubExtended::identity();
    let t2 = JubJubExtended::from(torsion_order_2());
    let t4 = JubJubExtended::from(torsion_order_4());
    let t8 = JubJubExtended::from(torsion_order_8());
    assert_ne!(t2, identity);
    assert_eq!(t2.double(), identity);
    assert_ne!(t4.double(), identity);
    assert_eq!(t4.double().double(), identity);
    assert_ne!(t8.double().double(), identity);
    assert_eq!(t8.double().double().double(), identity);
}

// The gadget's emitted gates get baked into downstream verifier keys; a
// refactor that alters a selector or a wire silently changes every consumer's
// key. Pin the layout to a digest captured when the gadget was introduced.
#[test]
fn torsion_free_layout_matches_golden() {
    // captured from `assert_torsion_free_point` at its introduction
    const GOLDEN: [u8; 32] = [
        29, 237, 27, 86, 26, 113, 3, 36, 200, 203, 232, 100, 142, 46, 26, 186,
        229, 225, 226, 228, 94, 68, 79, 22, 245, 233, 57, 1, 14, 37, 206, 53,
    ];

    let mut composer = Composer::initialized();
    let point = composer.append_point(prime_order_point());
    composer.assert_torsion_free_point(point);
    assert_eq!(
        gate_digest(&composer.constraints),
        GOLDEN,
        "assert_torsion_free_point gate layout drifted — verifier keys of \
         every consumer circuit change",
    );
}

#[test]
fn honest_members_verify() {
    let (prover, verifier, mut rng) = setup();

    // the identity is the subgroup's neutral element and must be admitted
    assert_verifies(
        &prover,
        &verifier,
        &mut rng,
        &TorsionFreeCircuit::default(),
    );
    assert_verifies(
        &prover,
        &verifier,
        &mut rng,
        &TorsionFreeCircuit::honest(prime_order_point()),
    );
}

// The production path rejects every non-member: a prime-order point tampered
// with each torsion order, a bare torsion point, and an off-curve point.
#[test]
fn non_members_rejected() {
    let (prover, _, mut rng) = setup();
    let accepted = TorsionFreeCircuit::honest(prime_order_point());
    let base = JubJubExtended::from(prime_order_point());

    let torsions = [
        ("order-2 tamper", torsion_order_2()),
        ("order-4 tamper", torsion_order_4()),
        ("order-8 tamper", torsion_order_8()),
    ];
    for (case, torsion) in torsions {
        let evil: JubJubAffine = (base + JubJubExtended::from(torsion)).into();
        assert!(
            !bool::from(JubJubExtended::from(evil).is_torsion_free()),
            "{case}: tampered point must not be torsion-free"
        );
        assert_rejected(
            &prover,
            &mut rng,
            &accepted,
            &TorsionFreeCircuit::honest(evil),
            case,
        );
    }

    assert_rejected(
        &prover,
        &mut rng,
        &accepted,
        &TorsionFreeCircuit::honest(torsion_order_2()),
        "bare order-2 point",
    );
    assert_rejected(
        &prover,
        &mut rng,
        &accepted,
        &TorsionFreeCircuit::honest(off_curve_zero()),
        "off-curve (0, 0)",
    );
}

// A prover free to choose `Q` cannot open the gadget for a non-member: every
// strategy — the "best possible" `[8⁻¹]·point`, the identity, the point
// itself, torsion points, an off-curve value — fails some constraint.
#[test]
fn injected_q_rejected() {
    let (prover, _, mut rng) = setup();
    let accepted = TorsionFreeCircuit::honest(prime_order_point());

    let evil: JubJubAffine = (JubJubExtended::from(prime_order_point())
        + JubJubExtended::from(torsion_order_2()))
    .into();
    let q_best: JubJubAffine = (JubJubExtended::from(evil) * EIGHT_INV).into();
    // sanity: even the best on-curve candidate misses `evil` by its torsion
    // component, so no satisfying assignment should exist at all
    let q8 = JubJubExtended::from(q_best).double().double().double();
    assert_ne!(JubJubAffine::from(q8), evil);

    let strategies = [
        ("Q = [8⁻¹]·point", q_best),
        ("Q = identity", JubJubAffine::identity()),
        ("Q = the point itself", evil),
        ("Q = order-8 torsion", torsion_order_8()),
        ("Q = order-2 torsion", torsion_order_2()),
        ("Q = off-curve (0, 0)", off_curve_zero()),
    ];
    for (case, q) in strategies {
        assert_rejected(
            &prover,
            &mut rng,
            &accepted,
            &TorsionFreeCircuit::inject_q(evil, q),
            case,
        );
    }

    // an off-curve input point stays rejected under Q injection as well
    let strategies = [
        ("off-curve point, Q = identity", JubJubAffine::identity()),
        ("off-curve point, Q = off-curve (0, 0)", off_curve_zero()),
        ("off-curve point, Q = order-8 torsion", torsion_order_8()),
    ];
    for (case, q) in strategies {
        assert_rejected(
            &prover,
            &mut rng,
            &accepted,
            &TorsionFreeCircuit::inject_q(off_curve_zero(), q),
            case,
        );
    }
}

// A forgery of the on-curve row: point and `Q` both `(0, 0)`, with the row's
// intermediates forged to `(u² = 0, v² = 1, u²·v² = 0)`. The curve-equation
// gate is then satisfied, the doubling chain honestly maps `(0, 0)` back to
// `(0, 0)`, and the final equality holds — the only constraint left standing
// between this assignment and acceptance is the multiplication gate binding
// `v²` to `Q`'s ordinate. If that gate ever stops binding, this test is the
// alarm.
#[test]
fn forged_on_curve_row_rejected() {
    let (prover, _, mut rng) = setup();
    let accepted = TorsionFreeCircuit::honest(prime_order_point());

    let rejected = TorsionFreeCircuit {
        point: off_curve_zero(),
        mode: Mode::ForgeOnCurveRow {
            q: off_curve_zero(),
            u2: BlsScalar::zero(),
            v2: BlsScalar::one(),
            u2v2: BlsScalar::zero(),
        },
    };
    assert_rejected(
        &prover,
        &mut rng,
        &accepted,
        &rejected,
        "forged on-curve row",
    );
}

// A forgery of the doubling chain: for a torsion-tampered `point` and the
// honest `Q = [8⁻¹]·point`, forge the first doubling's output to the
// chain-jump target `S = [4⁻¹]·(subgroup part) + order-8 torsion`, whose two
// remaining honest doublings land exactly on `point` ([4]·S == point). The
// on-curve row, the later doublings and the final equality are all then
// honestly satisfied — the only constraints left standing are the widget
// identities binding the forged doubling's output. If they ever stop
// binding, this test is the alarm.
#[test]
fn forged_doubling_chain_rejected() {
    let (prover, _, mut rng) = setup();
    let accepted = TorsionFreeCircuit::honest(prime_order_point());

    let base = JubJubExtended::from(prime_order_point());
    let evil: JubJubAffine =
        (base + JubJubExtended::from(torsion_order_2())).into();
    let q: JubJubAffine = (JubJubExtended::from(evil) * EIGHT_INV).into();

    let four_inv = JubJubScalar::from(4u64)
        .invert()
        .expect("4 is invertible mod r");
    let s: JubJubAffine =
        (base * four_inv + JubJubExtended::from(torsion_order_8())).into();
    // sanity: the jump works — [4]·S == point, so every gate after the
    // forged doubling is honestly satisfied — and the forged output really
    // differs from the honest doubling [2]·Q
    let s_ext = JubJubExtended::from(s);
    assert_eq!(JubJubAffine::from(s_ext.double().double()), evil);
    assert_ne!(JubJubAffine::from(JubJubExtended::from(q).double()), s);

    let rejected = TorsionFreeCircuit {
        point: evil,
        mode: Mode::ForgeFirstDoubling { q, s },
    };
    assert_rejected(
        &prover,
        &mut rng,
        &accepted,
        &rejected,
        "forged doubling chain",
    );
}
