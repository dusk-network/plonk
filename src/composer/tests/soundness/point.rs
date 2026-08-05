// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regressions for `assert_torsion_free_point` and
//! `component_add_point`.
//!
//! The subgroup check must admit exactly the prime-order subgroup: honest
//! members (identity included) prove, while on-curve torsion components and
//! off-curve points are rejected. The threat model is a prover free to assign
//! *every* witness, not just the input point — so beyond the production entry
//! point (which derives the honest `Q`) the forgeries here inject
//! attacker-chosen `Q` values and forge each family of intermediate witnesses
//! directly: the on-curve row's squares and the doubling chain's outputs.
//!
//! The curve-addition gadget keeps its formula below degree 4 by allocating a
//! helper witness for `x_1 * y_2`. Its widget identity folds three residuals as
//! `xy + κ·x3 + κ²·y3`: the first binds that wire, the other two are the
//! output-coordinate checks, which consume the wire in place of the product.
//! The binding term is the wire's only in-gate pin, and the output checks solve
//! for a matching `(x_3, y_3)` at every wire value but the two poles
//! `±1/(D*y_1*x_2)`, where one check degenerates: at `+` the `y_3` check
//! collapses to `y_1*y_2 + x_1*x_2 = 0` and leaves `y_3` free, at `-` the `x_3`
//! check collapses to `x1_y2 + y1_x2 = 0` and leaves `x_3` free. **No case
//! below exercises either** — `forced_output` inverts both denominators, so it
//! panics on a pole rather than constructing one. Neither is an escape hatch,
//! but that is an argument rather than a test: with `a = -1` a square and `d` a
//! non-square (asserted in [`subgroup_parameters_hold`]) the addition law is
//! complete, so no on-curve addends put the *honest* wire on a pole, and a
//! forged pole wire still carries a nonzero binding residual.
//!
//! So without that term a prover picks the wire freely and still satisfies
//! every other constraint — including, as the steering case shows, picking it
//! so that the claimed sum of two *public* addends carries an x-coordinate of
//! the attacker's choosing. Those forgeries reproduce the production emission
//! with only the wire falsified and the coordinates its own checks force;
//! `forced_output` does that solving, so it is itself pinned against
//! `compute_quotient_i`. That pin is the only reach from `composer` into
//! `proof_system::widget`, and is deliberate: it exists to tie this module's
//! `forced_output` to the widget's own identity, and building the `ProverKey`
//! by struct literal makes a new field on it break the build here rather than
//! silently weaken the pin.

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{
    EDWARDS_D, GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
};
use ff::Field;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{assert_rejected, assert_verifies, gate_digest};
use crate::composer::point::EIGHT_INV;
use crate::composer::{
    Composer, Constraint, TorsionFreeWitnessPoint, Witness, WitnessPoint,
};
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::prelude::{
    Circuit, Compiler, Error, PlonkVersion, Prover, PublicParameters, Verifier,
};
use crate::proof_system::widget::ecc::curve_addition;

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
            Mode::Honest => {
                composer.assert_torsion_free_point(point);
            }
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
                let q2 = composer.add_point_gates(q, q);
                let q4 = composer.add_point_gates(q2, q2);
                let q8 = composer.add_point_gates(q4, q4);
                composer.assert_equal_point(point, q8);
            }
            Mode::ForgeFirstDoubling { q, s } => {
                // Mirror `assert_torsion_free_gates` with only the first
                // doubling's output witnesses forged to `s`; the remaining
                // doublings run honestly from the forged point.
                let q = composer.append_point(*q);
                honest_on_curve_row(composer, q);
                let q2 = forged_double(composer, q, *s);
                let q4 = composer.add_point_gates(q2, q2);
                let q8 = composer.add_point_gates(q4, q4);
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

// `component_mul_point` promises consumers an unchanged layout now that
// `component_select_identity` constrains its bit: the loop must keep calling
// the raw `select_identity_gates` seam. Routing it through the public method
// would add a redundant boolean gate per round and silently move every
// consumer's verifier key. Pin the layout to a digest captured when the
// promise was made.
#[test]
fn mul_point_layout_matches_golden() {
    // captured from `component_mul_point` when `component_select_identity`
    // gained its boolean constraint
    const GOLDEN: [u8; 32] = [
        250, 132, 56, 170, 228, 252, 166, 13, 108, 124, 132, 6, 89, 188, 88,
        247, 231, 121, 77, 144, 115, 248, 63, 117, 196, 123, 96, 37, 146, 174,
        156, 68,
    ];

    let mut composer = Composer::initialized();
    let scalar = composer.append_witness(JubJubScalar::from(17u64));
    let point = composer.append_point(prime_order_point());
    let point = TorsionFreeWitnessPoint::new_unchecked(point);
    composer.component_mul_point(scalar, point);
    assert_eq!(
        gate_digest(&composer.constraints),
        GOLDEN,
        "component_mul_point gate layout drifted — verifier keys of every \
         consumer circuit change",
    );
}

// Constant points are validated natively at circuit build: members (the
// identity included) are appended, torsion components are refused before
// they can enter the circuit description.
#[test]
fn constant_points_validated_natively() {
    let mut composer = Composer::initialized();

    assert!(composer.append_constant_point(prime_order_point()).is_ok());
    assert!(
        composer
            .append_constant_point(JubJubAffine::identity())
            .is_ok()
    );

    for point in [
        torsion_order_2(),
        torsion_order_4(),
        torsion_order_8(),
        off_curve_zero(),
    ] {
        assert_eq!(
            composer.append_constant_point(point).unwrap_err(),
            Error::JubJubPointNotTorsionFree,
        );
    }
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

fn invert(value: BlsScalar) -> BlsScalar {
    Option::from(value.invert()).expect("the denominator is invertible")
}

/// The coordinates the widget's output checks force once the helper wire
/// carries `x1_y2`. Each check is linear in its own coordinate, so each has one
/// solution: `x_3 * (1 + D*x1_y2*y1_x2) = x1_y2 + y1_x2` and
/// `y_3 * (1 - D*x1_y2*y1_x2) = y_1*y_2 + x_1*x_2`.
///
/// `compute_quotient_i` weights these by `κ`/`κ²`; a factor on a residual that
/// must vanish outright changes nothing. Pinned against the widget in
/// [`forced_output_satisfies_the_widget_output_checks`].
fn forced_output(
    x_1: BlsScalar,
    y_1: BlsScalar,
    x_2: BlsScalar,
    y_2: BlsScalar,
    x1_y2: BlsScalar,
) -> (BlsScalar, BlsScalar) {
    let y1_x2 = y_1 * x_2;
    let skew = EDWARDS_D * x1_y2 * y1_x2;

    let x_3 = (x1_y2 + y1_x2) * invert(BlsScalar::one() + skew);
    let y_3 = (y_1 * y_2 + x_1 * x_2) * invert(BlsScalar::one() - skew);

    (x_3, y_3)
}

/// The helper-wire value whose forced output x-coordinate is `x_3`: the `x_3`
/// check solved for the wire instead of the coordinate. This is what turns a
/// free choice of the wire into a free choice of the claimed sum's
/// x-coordinate.
fn wire_forcing_x3(
    y_1: BlsScalar,
    x_2: BlsScalar,
    x_3: BlsScalar,
) -> BlsScalar {
    let y1_x2 = y_1 * x_2;

    (y1_x2 - x_3) * invert(x_3 * EDWARDS_D * y1_x2 - BlsScalar::one())
}

/// The point the steering forgery aims at: a real curve point that is not the
/// sum, so the stolen x-coordinate is one that could legitimately have arisen.
fn steering_target() -> JubJubAffine {
    JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::from(7u64))
}

/// The forged wires, shared so the circuit-level forgeries and the widget-level
/// pin cannot drift apart.
fn forged_wires(
    honest_wire: BlsScalar,
    y_1: BlsScalar,
    x_2: BlsScalar,
) -> [(&'static str, BlsScalar); 3] {
    [
        ("helper wire off by one", honest_wire + BlsScalar::one()),
        ("helper wire zeroed", BlsScalar::zero()),
        (
            "helper wire steering the sum's x-coordinate",
            wire_forcing_x3(y_1, x_2, steering_target().get_u()),
        ),
    ]
}

/// Adds two public points and exposes the sum publicly. Both addends being
/// public leaves the gadget's intermediates as the prover's only freedom.
struct CurveAdditionCircuit {
    a: JubJubAffine,
    b: JubJubAffine,
    claimed_sum: JubJubAffine,
    forged_x1_y2: Option<BlsScalar>,
}

impl Default for CurveAdditionCircuit {
    fn default() -> Self {
        Self::honest(GENERATOR_EXTENDED, GENERATOR_EXTENDED.double())
    }
}

impl CurveAdditionCircuit {
    fn honest(a: JubJubExtended, b: JubJubExtended) -> Self {
        Self {
            a: a.into(),
            b: b.into(),
            claimed_sum: (a + b).into(),
            forged_x1_y2: None,
        }
    }

    /// Same public addends, helper wire set to `x1_y2`, sum claimed to be what
    /// the output checks then force. That sum is off-curve in general — nothing
    /// in the gadget constrains the output to the curve, so the binding term is
    /// the whole of the defence.
    fn forged(a: JubJubAffine, b: JubJubAffine, x1_y2: BlsScalar) -> Self {
        let (x_3, y_3) =
            forced_output(a.get_u(), a.get_v(), b.get_u(), b.get_v(), x1_y2);

        Self {
            a,
            b,
            claimed_sum: JubJubAffine::from_raw_unchecked(x_3, y_3),
            forged_x1_y2: Some(x1_y2),
        }
    }
}

impl Circuit for CurveAdditionCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let a = composer.append_public_point(self.a);
        let b = composer.append_public_point(self.b);

        // The addends are the generator and its double: subgroup constants, so
        // membership is established rather than merely vouched for, which is
        // what `new_unchecked` requires. The wrap adds no constraints, leaving
        // the layout under test untouched, and the binding exercised here does
        // not depend on membership either way.
        let sum = match self.forged_x1_y2 {
            None => composer
                .component_add_point(
                    TorsionFreeWitnessPoint::new_unchecked(a),
                    TorsionFreeWitnessPoint::new_unchecked(b),
                )
                .into(),
            Some(x1_y2) => {
                // `add_point_gates`' emission by hand, the private path
                // `component_add_point` delegates to — witness order, selectors
                // and wiring unchanged — with the helper wire and output
                // coordinates replaced. `assert_rejected` compares this layout
                // against the honest one, so drift fails the test.
                //
                // The coordinates come from `claimed_sum` rather than a second
                // `forced_output` call: were they to disagree, the unsatisfied
                // gate would be `assert_equal_public_point` and nothing would
                // notice, since public-input values live outside `Gate`.
                let x_1_y_2 = composer.append_witness(x1_y2);
                let x_3 = composer.append_witness(self.claimed_sum.get_u());
                let y_3 = composer.append_witness(self.claimed_sum.get_v());

                let constraint =
                    Constraint::new().a(*a.x()).b(*a.y()).c(*b.x()).d(*b.y());
                let constraint =
                    Constraint::group_add_variable_base(&constraint);
                composer.append_custom_gate(constraint);

                let constraint = Constraint::new().a(x_3).b(y_3).d(x_1_y_2);
                composer.append_custom_gate(constraint);

                WitnessPoint::new(x_3, y_3)
            }
        };

        composer.assert_equal_public_point(sum, self.claimed_sum);

        Ok(())
    }
}

fn compile(pp: &PublicParameters) -> (Prover, Verifier) {
    Compiler::compile::<CurveAdditionCircuit>(pp, b"curve-addition-soundness")
        .expect("compile curve-addition soundness circuit")
}

#[test]
fn curve_addition_binds_the_helper_wire() {
    assert_eq!(PlonkVersion::current(), PlonkVersion::V3);

    let mut rng = StdRng::seed_from_u64(0x_add_9_0117);
    let pp = PublicParameters::setup(1 << 8, &mut rng).expect("setup");
    let (prover, verifier) = compile(&pp);

    let honest = CurveAdditionCircuit::default();
    assert_verifies(&prover, &verifier, &mut rng, &honest);

    let x_1 = honest.a.get_u();
    let y_1 = honest.a.get_v();
    let x_2 = honest.b.get_u();
    let y_2 = honest.b.get_v();
    let honest_wire = x_1 * y_2;

    // On the honest wire, solving the output checks must land on
    // `dusk-jubjub`'s own sum — what ties `forced_output` to the real curve.
    let (honest_x_3, honest_y_3) =
        forced_output(x_1, y_1, x_2, y_2, honest_wire);
    assert_eq!(
        JubJubAffine::from_raw_unchecked(honest_x_3, honest_y_3),
        honest.claimed_sum,
        "solving the output checks on the honest wire must give the true sum",
    );

    let target = steering_target();
    assert_ne!(target.get_u(), honest.claimed_sum.get_u());

    let [off_by_one, zeroed, steering] = forged_wires(honest_wire, y_1, x_2);

    // Round-trip `wire_forcing_x3` back through `forced_output`: its wire is
    // the one aiming the claimed sum at `target`. The reach of the attack.
    assert_eq!(
        CurveAdditionCircuit::forged(honest.a, honest.b, steering.1)
            .claimed_sum
            .get_u(),
        target.get_u(),
        "the steering wire must aim the claimed sum at the target",
    );

    for (case, forged_wire) in [off_by_one, zeroed, steering] {
        assert_ne!(forged_wire, honest_wire, "{case}: must forge the wire");

        let forgery =
            CurveAdditionCircuit::forged(honest.a, honest.b, forged_wire);

        assert_rejected(&prover, &mut rng, &honest, &forgery, case);
    }
}

/// The forgeries rest on `forced_output`'s coordinates satisfying the widget's
/// own output checks; nothing else here asserts that. The honest-witness
/// comparison above pins one point of it, which an algebra change that still
/// accepted the true Edwards sum would survive. This covers the forged wires.
///
/// A single-`1` selector evaluation reduces `compute_quotient_i` to the
/// identity times the challenge, so matching the binding residual says `κ·x3 +
/// κ²·y3` vanishes — one equation in two unknowns, which a matched nonzero pair
/// also satisfies. Two challenges with distinct squares force both to zero.
///
/// That equality would also hold for a widget with both output checks deleted,
/// the identity then being the binding term outright, so each coordinate is
/// perturbed and required to move the identity off it.
#[test]
fn forced_output_satisfies_the_widget_output_checks() {
    let selector = Evaluations::from_vec_and_domain(
        Vec::from([BlsScalar::one()]),
        EvaluationDomain::new(1).expect("a one-element domain"),
    );
    let prover_key = curve_addition::ProverKey {
        q_variable_group_add: (Polynomial::zero(), selector),
    };

    // Arbitrary, beyond their squares differing so the two equations they give
    // in the output residuals are independent.
    let challenges = [
        BlsScalar::from(0x0add_0117u64),
        BlsScalar::from(0x7b0f_fd83u64),
    ];
    assert_ne!(
        challenges[0].square(),
        challenges[1].square(),
        "the two challenges must weight the output residuals differently",
    );

    let honest = CurveAdditionCircuit::default();
    let x_1 = honest.a.get_u();
    let y_1 = honest.a.get_v();
    let x_2 = honest.b.get_u();
    let y_2 = honest.b.get_v();
    let honest_wire = x_1 * y_2;

    let [off_by_one, zeroed, steering] = forged_wires(honest_wire, y_1, x_2);

    for (case, wire) in
        [("honest wire", honest_wire), off_by_one, zeroed, steering]
    {
        let (x_3, y_3) = forced_output(x_1, y_1, x_2, y_2, wire);

        for challenge in challenges {
            let binding_term = (honest_wire - wire) * challenge;
            let identity = |x_3, y_3| {
                prover_key.compute_quotient_i(
                    0, &challenge, &x_1, &x_3, &y_1, &y_3, &x_2, &y_2, &wire,
                )
            };

            assert_eq!(
                identity(x_3, y_3),
                binding_term,
                "{case}: the widget's identity must reduce to the binding term",
            );

            // Each check carries a nonzero coefficient on its own coordinate
            // (`1 ± skew` — nonzero here, or `forced_output` would have
            // panicked), so moving that coordinate must move the identity.
            // Deleting both checks fails here, not above.
            assert_ne!(
                identity(x_3 + BlsScalar::one(), y_3),
                binding_term,
                "{case}: the x_3 check must constrain x_3",
            );
            assert_ne!(
                identity(x_3, y_3 + BlsScalar::one()),
                binding_term,
                "{case}: the y_3 check must constrain y_3",
            );
        }
    }
}

/// `assert_rejected` only checks the hand-copied emission against the gadget —
/// an edit to both stays green while moving every deployed verifier key holding
/// a curve addition. This pins the layout on its own.
#[test]
fn component_add_point_layout_matches_golden() {
    // `gate_digest` captured from `component_add_point` as released in
    // `v0.22.1` (`fc39ad3`), and unchanged since — across both the refactor
    // that moved the emission into `add_point_gates` and the composer split
    // that moved it into this module.
    const GOLDEN: [u8; 32] = [
        228, 59, 231, 43, 120, 95, 179, 34, 228, 43, 10, 248, 22, 142, 41, 174,
        127, 155, 191, 155, 9, 56, 184, 82, 223, 173, 215, 132, 79, 23, 42, 4,
    ];

    let mut composer = Composer::initialized();
    let a = composer.append_point(GENERATOR_EXTENDED);
    let b = composer.append_point(GENERATOR_EXTENDED.double());
    composer.component_add_point(
        TorsionFreeWitnessPoint::new_unchecked(a),
        TorsionFreeWitnessPoint::new_unchecked(b),
    );

    assert_eq!(
        gate_digest(&composer.constraints),
        GOLDEN,
        "component_add_point's gate layout drifted from the deployed \
         verifier keys",
    );
}
