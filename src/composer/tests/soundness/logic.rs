// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regressions for `append_logic_component`: its input binding, its
//! canonical truncation, and its per-quad product wire.
//!
//! Each is a witness the prover is free on unless a constraint pins it, and
//! each gets its own forgery below. The gadget once rebuilt its output from the
//! bits of `a`/`b` without wiring the input witnesses into any gate, so a
//! cheating prover could satisfy the identical gate layout (and so the same
//! verifier key) with accumulators decoupled from the inputs; the closing
//! truncation binding admits the `+ r` alias unless the canonical guard rules
//! it out; and the product wire the widget carries per quad is pinned by a
//! single term of the logic identity. `append_logic_component` constrains all
//! three today, and these tests guard against a regression of each.
//!
//! Exhibiting such an assignment requires emitting the logic gate with forged
//! witnesses, which needs the crate-private logic selector — hence these tests
//! live in-crate rather than in `tests/`. Each is a full
//! `compile -> prove -> verify` round-trip against the real public gadget.
//!
//! Every forgery goes through [`assert_rejected`], which requires it to
//! emit the honest gate layout and then to be rejected by an unsatisfied
//! constraint — so a rejection here can only come from the constraint that
//! forgery targets, never from a layout mismatch or an unrelated proving error.

use core::cmp;

use dusk_bls12_381::{BlsScalar, G1Affine, G1Projective};
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{
    assert_rejected, assert_verifies, fits, gate_digest, truncate,
};
use crate::bit_iterator::BitIterator8;
use crate::commitment_scheme::Commitment;
use crate::composer::{Composer, Constraint, WiredWitness, Witness};
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::prelude::{
    Circuit, Compiler, Error, Prover, PublicParameters, Verifier,
};
use crate::proof_system::linearization_poly::ProofEvaluations;
use crate::proof_system::widget::logic;
use crate::proof_system::widget::logic::proverkey::delta_xor_and;

// The width `ForgeCircuit` operates on: the low 32 bits.
const FORGE_BIT_PAIRS: usize = 16;

// Inputs pinned to constants so they are identical for every prover. Both fit
// in `FORGE_BIT_PAIRS * 2` bits, so the result is exactly `input_a ^ input_b`
// (or `input_a & input_b`).
//
// Their quad decompositions are `[0, 1, 2, 3]` and `[3, 2, 1, 0]` repeated
// four times, so the round at [`FORGED_ROUND`] carries the quad pair `(1, 2)`.
// That pair is load-bearing rather than incidental — see [`FORGED_ROUND`]. It
// is never assumed: [`LogicRow`] reads the quads back off the emitted gate, so
// the tests rest on what the gadget builds rather than on this note.
fn input_a() -> BlsScalar {
    BlsScalar::from(0x1b1b_1b1b_u64)
}
fn input_b() -> BlsScalar {
    BlsScalar::from(0xe4e4_e4e4_u64)
}

/// The round whose per-quad product wire the forgery falsifies.
///
/// `delta_xor_and` is a cubic in that wire with leading coefficient `-8`, and
/// the honest wire `a * b` is always one of its roots. Whether a *second* root
/// exists over the field is a property of the quad pair alone, not of the
/// selector: on two-bit quads `a + b = (a ^ b) + 2 * (a & b)`, so the
/// residual's selector-dependent part, `q_c * (9d - 3(a + b)) + 3(a + b + d)`,
/// collapses to `12 * (a & b)` under both. The 32 legal rows are therefore 16
/// distinct cubics, and on most of them the wire cannot be moved at all:
/// deflating by the honest root leaves 10 of the 16 with a non-residue
/// discriminant — 20 of the 32 rows. There `c_3` and `c_4` are jointly rigid,
/// and a test built on such a pair would forge nothing and pass vacuously. The
/// binding this module pins is therefore weaker than what the widget enforces
/// on most rows.
///
/// `(1, 2)` and `(2, 1)` are the pairs whose second root is `0`: the cubic is
/// `-8w³ - 54w² + 140w`, the honest wire `2` is one root and `0` is another, so
/// forging the wire to `0` satisfies `c_4` exactly and leaves `c_3` as the only
/// objection.
const FORGED_ROUND: usize = 1;

/// The value [`FORGED_ROUND`]'s product wire is forged to.
const FORGED_WIRE: u64 = 0;

/// One round of the logic loop, as the composer emits it: the two selectors and
/// the seven wire values the widget's identity reads.
///
/// The widget takes each quad as the difference between this gate's accumulator
/// and the next gate's, so a round spans two gates. Everything here is read off
/// the built circuit rather than recomputed, so the pin describes the row the
/// gadget actually emits instead of restating the gadget's bit slicing and
/// hoping the two stay in step.
struct LogicRow {
    q_c: BlsScalar,
    q_logic: BlsScalar,
    a_eval: BlsScalar,
    a_w_eval: BlsScalar,
    b_eval: BlsScalar,
    b_w_eval: BlsScalar,
    c_eval: BlsScalar,
    d_eval: BlsScalar,
    d_w_eval: BlsScalar,
}

impl LogicRow {
    /// Round `round` of the logic loop `circuit` emits.
    fn read(circuit: &ForgeCircuit, round: usize) -> Self {
        let mut composer = Composer::initialized();
        circuit.circuit(&mut composer).expect("circuit builds");

        // The loop's gates are the ones carrying `q_logic`; the closing pad and
        // the binding gates do not.
        let loop_gates: Vec<usize> = composer
            .constraints
            .iter()
            .enumerate()
            .filter(|(_, gate)| gate.q_logic != BlsScalar::zero())
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            loop_gates.len(),
            FORGE_BIT_PAIRS,
            "the logic loop must emit one gate per quad",
        );
        assert_eq!(
            loop_gates[round + 1],
            loop_gates[round] + 1,
            "the widget reads the next gate's accumulators, so the loop's \
             gates must be contiguous",
        );

        let gate = &composer.constraints[loop_gates[round]];
        let next = &composer.constraints[loop_gates[round] + 1];

        Self {
            q_c: gate.q_c,
            q_logic: gate.q_logic,
            a_eval: composer[gate.a],
            a_w_eval: composer[next.a],
            b_eval: composer[gate.b],
            b_w_eval: composer[next.b],
            c_eval: composer[gate.c],
            d_eval: composer[gate.d],
            d_w_eval: composer[next.d],
        }
    }

    /// The quad values the widget derives from the row: `a`, `b` and the output
    /// quad `d`, each the difference of two consecutive accumulators.
    fn quads(&self) -> (BlsScalar, BlsScalar, BlsScalar) {
        let four = BlsScalar::from(4u64);
        (
            self.a_w_eval - four * self.a_eval,
            self.b_w_eval - four * self.b_eval,
            self.d_w_eval - four * self.d_eval,
        )
    }
}

// An attacker's fork of [`Composer::append_logic_component`]: byte-identical
// gate emission, except the `a`-bits are sourced from `forged` instead of
// `self[a]`, so the returned witness is decoupled from the input witness `a`.
// This models a malicious prover that emits the honest gate layout while
// filling the per-quad accumulators with values unrelated to the inputs.
//
// It mirrors `append_logic_component` exactly so that, once that gadget binds
// its accumulators to its inputs, this fork inherits the binding gates too and
// the decoupled assignment becomes unsatisfiable.
//
// `forged_wire` is the second, independent axis: see [`forge_logic_loop`].
fn forge_logic_component<const BIT_PAIRS: usize>(
    composer: &mut Composer,
    a: Witness,
    b: Witness,
    forged: BlsScalar,
    forged_wire: Option<(usize, BlsScalar)>,
    is_component_xor: bool,
) -> Witness {
    let (d, left_acc_wit, right_acc_wit) = forge_logic_loop::<BIT_PAIRS>(
        composer,
        b,
        forged,
        forged_wire,
        is_component_xor,
    );

    // Mirror the honest gadget's binding. The binding wires the REAL `a`/`b` to
    // the (forged) accumulators, so the forged assignment is now unsatisfiable.
    composer.bind_logic_accumulators::<BIT_PAIRS>(
        a,
        b,
        left_acc_wit,
        right_acc_wit,
    );

    d
}

// The gate-emission loop shared by every fork: emits the identical logic gates
// as `append_logic_component` but falsifies the witnesses on two independent
// axes. Returns the output witness and the final left/right accumulator
// witnesses (so callers can attach the binding gates of their choice). Does NOT
// bind the inputs.
//
// The axes are kept separate because they exercise different constraints and
// each has a test that depends on the other staying honest:
//
// - `forged`: the `a`-bits are sourced from it instead of from `composer[a]`,
//   decoupling the accumulators from the constrained input.
// - `forged_wire`: `Some((round, w))` replaces that round's per-quad product
//   witness with `w`, leaving every accumulator honest.
fn forge_logic_loop<const BIT_PAIRS: usize>(
    composer: &mut Composer,
    b: Witness,
    forged: BlsScalar,
    forged_wire: Option<(usize, BlsScalar)>,
    is_component_xor: bool,
) -> (Witness, Witness, Witness) {
    let num_bits = cmp::min(BIT_PAIRS * 2, 254);
    let num_quads = num_bits >> 1;

    let bls_four = BlsScalar::from(4u64);
    let mut left_acc = BlsScalar::zero();
    let mut right_acc = BlsScalar::zero();
    let mut out_acc = BlsScalar::zero();

    // The first deviation from `append_logic_component`: `a`-bits come from
    // `forged`, not from `composer[a]`.
    let a_bits: Vec<_> = BitIterator8::new(forged.to_bytes())
        .skip(256 - num_bits)
        .collect();
    let b_bits: Vec<_> = BitIterator8::new(composer[b].to_bytes())
        .skip(256 - num_bits)
        .collect();

    let mut constraint = if is_component_xor {
        Constraint::logic_xor(&Constraint::new())
    } else {
        Constraint::logic(&Constraint::new())
    };

    for i in 0..num_quads {
        let idx = i * 2;

        let l = (a_bits[idx] as u8) << 1;
        let r = a_bits[idx + 1] as u8;
        let left_quad = l + r;
        let left_quad_bls = BlsScalar::from(left_quad as u64);

        let l = (b_bits[idx] as u8) << 1;
        let r = b_bits[idx + 1] as u8;
        let right_quad = l + r;
        let right_quad_bls = BlsScalar::from(right_quad as u64);

        let out_quad_bls = if is_component_xor {
            left_quad ^ right_quad
        } else {
            left_quad & right_quad
        } as u64;
        let out_quad_bls = BlsScalar::from(out_quad_bls);

        // The second deviation: one round's product witness is replaced
        // wholesale, leaving the accumulators below untouched.
        let prod_quad_bls = match forged_wire {
            Some((round, wire)) if round == i => wire,
            _ => BlsScalar::from((left_quad * right_quad) as u64),
        };

        left_acc = left_acc * bls_four + left_quad_bls;
        right_acc = right_acc * bls_four + right_quad_bls;
        out_acc = out_acc * bls_four + out_quad_bls;

        let wit_a = composer.append_witness(left_acc);
        let wit_b = composer.append_witness(right_acc);
        let wit_c = composer.append_witness(prod_quad_bls);
        let wit_d = composer.append_witness(out_acc);

        constraint = constraint.c(wit_c);
        composer.append_custom_gate(constraint);
        constraint = constraint.a(wit_a).b(wit_b).d(wit_d);
    }

    let left_acc_wit = constraint.witness(WiredWitness::A);
    let right_acc_wit = constraint.witness(WiredWitness::B);
    let d = constraint.witness(WiredWitness::D);
    let constraint = Constraint::new().a(left_acc_wit).b(right_acc_wit).d(d);
    composer.append_custom_gate(constraint);

    (d, left_acc_wit, right_acc_wit)
}

// One circuit shape; the fields select the prover, and each may be set on its
// own.
//   and: true -> the AND gadget instead of the XOR one. Only the widget-level
//                pin uses it, to check the gadget pairs each `q_c` with the
//                matching output quad; see that test for why both arms earn
//                their place.
//   forged_a: Some(bits) -> accumulators built from `bits` instead of `a`, so
//                the result is `bits ^ input_b`.
//   forged_wire: Some((round, w)) -> that round's per-quad product witness is
//                `w`; every accumulator, and so the result, stays honest.
// All defaults is the honest XOR gadget.
#[derive(Default)]
struct ForgeCircuit {
    and: bool,
    forged_a: Option<BlsScalar>,
    forged_wire: Option<(usize, BlsScalar)>,
}

impl Circuit for ForgeCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let is_xor = !self.and;

        // Pin both inputs so they cannot differ between provers.
        let a = composer.append_witness(input_a());
        let b = composer.append_witness(input_b());
        composer.assert_equal_constant(a, input_a(), None);
        composer.assert_equal_constant(b, input_b(), None);

        let result = match (self.forged_a, self.forged_wire) {
            (None, None) if is_xor => {
                composer.append_logic_xor::<FORGE_BIT_PAIRS>(a, b)
            }
            (None, None) => composer.append_logic_and::<FORGE_BIT_PAIRS>(a, b),
            (forged_a, forged_wire) => {
                forge_logic_component::<FORGE_BIT_PAIRS>(
                    composer,
                    a,
                    b,
                    forged_a.unwrap_or_else(input_a),
                    forged_wire,
                    is_xor,
                )
            }
        };

        // Expose the result as a public input.
        let forged_a = self.forged_a.unwrap_or_else(input_a);
        let claimed = if is_xor {
            forged_a ^ input_b()
        } else {
            forged_a & input_b()
        };
        let public = composer.append_public(claimed);
        composer.assert_equal(result, public);

        Ok(())
    }
}

#[test]
fn logic_xor_binds_output_to_inputs() {
    let mut rng = StdRng::seed_from_u64(0x10_91c);
    let pp =
        PublicParameters::setup(1 << 12, &mut rng).expect("public parameters");

    // Verifier key compiled from the HONEST gadget.
    let (prover, verifier): (Prover, Verifier) =
        Compiler::compile::<ForgeCircuit>(&pp, b"logic-gate-soundness")
            .expect("compile");

    let honest_result = input_a() ^ input_b();

    // Control: the honest gadget computes the true XOR, and it verifies.
    let honest = ForgeCircuit::default();
    assert_eq!(
        assert_verifies(&prover, &verifier, &mut rng, &honest),
        vec![honest_result],
    );

    // Forge: same gate layout, accumulators decoupled from the constrained `a`.
    // Before the fix this proved and verified against the honest verifier key;
    // the binding now makes the assignment unsatisfiable.
    let forged_a = BlsScalar::from(0x1234_5678_u64);
    assert_ne!(forged_a ^ input_b(), honest_result);
    let forged = ForgeCircuit {
        forged_a: Some(forged_a),
        ..Default::default()
    };

    assert_rejected(
        &prover,
        &mut rng,
        &honest,
        &forged,
        "decoupled accumulators",
    );
}

// ---------------------------------------------------------------------------
// Per-quad product-wire regression.
//
// To keep the logic identity below degree 4 the widget allocates a witness `w`
// per quad, meant to hold `a * b`, and folds it into two of its five residuals:
// `c_3 = (w - a·b)·κ³`, which is the wire's only pin, and
// `c_4 = delta_xor_and(a, b, w, d, q_c)·κ⁴`, which consumes it as a cubic. The
// accumulator forgery above moves `a`, `b` and `d`; it never touches `w`.
//
// Forging `w` normally breaks `c_3` and `c_4` together, and on most quad pairs
// they are jointly rigid — see `FORGED_ROUND`. On the pairs where they are not,
// `c_3` stands alone, and these two tests require it to hold.
// ---------------------------------------------------------------------------

/// The forgery, end to end: the honest gate stream with one round's product
/// witness substituted.
///
/// `w` propagates nowhere else. It appears in `c_3` and `c_4` and in no other
/// residual; the row carries `q_logic`, so the arithmetic widget never reads
/// it; and the composer appends a fresh witness per quad that no other gate
/// wires to, so no copy constraint reaches it either. Every accumulator, the
/// closing binding and the claimed public output all stay honest, so `c_3` is
/// the only constraint that can turn this proof away —
/// [`forged_product_wire_reduces_the_logic_identity_to_its_binding_term`] pins
/// that it is what does.
#[test]
fn logic_xor_binds_the_per_quad_product_wire() {
    let forgery = ForgeCircuit {
        forged_wire: Some((FORGED_ROUND, BlsScalar::from(FORGED_WIRE))),
        ..Default::default()
    };
    let row = LogicRow::read(&forgery, FORGED_ROUND);
    let (a, b, _) = row.quads();
    assert_eq!(
        (a, b),
        (BlsScalar::from(1u64), BlsScalar::from(2u64)),
        "the forged round must carry a quad pair whose product wire has a \
         second root over the field; see `FORGED_ROUND`",
    );
    assert_ne!(
        row.c_eval,
        a * b,
        "the forged wire must differ from the honest product",
    );

    let mut rng = StdRng::seed_from_u64(0x10_91e);
    let pp =
        PublicParameters::setup(1 << 12, &mut rng).expect("public parameters");

    // Verifier key compiled from the HONEST gadget.
    let (prover, verifier): (Prover, Verifier) =
        Compiler::compile::<ForgeCircuit>(&pp, b"logic-product-wire")
            .expect("compile");

    let honest = ForgeCircuit::default();
    assert_eq!(
        assert_verifies(&prover, &verifier, &mut rng, &honest),
        vec![input_a() ^ input_b()],
    );

    assert_rejected(
        &prover,
        &mut rng,
        &honest,
        &forgery,
        "forged per-quad product wire",
    );
}

/// Pins the rejection above to `c_3` rather than to the widget in general, by
/// evaluating the identity at the forged row directly.
///
/// The identity is `α · (c_0 + c_1·κ + c_2·κ² + c_3·κ³ + c_4·κ⁴)` with
/// `κ = α²`, a degree-4 polynomial in `κ`. Requiring it to equal the binding
/// monomial `α·κ³·(w - a·b)` at five `κ` with distinct values forces every
/// coefficient: the three `delta` residuals and `c_4` vanish, and `c_3` is
/// exactly the binding term. Fewer points would leave the residuals room to
/// cancel against each other.
///
/// That equality would also hold for a widget with `c_4` deleted, which is the
/// residual whose vanishing at the forged wire makes the forgery possible at
/// all, so `q_c` — which enters the identity only through `c_4` — is perturbed
/// and required to move it. The three `delta` residuals cannot be isolated that
/// way, since `a`, `b` and `d` also feed `c_3` and `c_4`; they bound the quads
/// to `{0,1,2,3}`, an axis this module does not claim to cover.
///
/// The widget computes the identity in three places: the prover's quotient, the
/// prover's linearization, and the verifier key's linearization commitment. All
/// three are asserted, so a weakening cannot hide in one copy. The verifier key
/// is built from two distinct commitments and both of its output vectors are
/// checked, so the commitment the widget weights is pinned as well as the
/// scalar it weights it by. The verifier folds `q_logic` into that commitment
/// rather than into its scalar, which is why its expected scalar is the bracket
/// alone while the two prover copies carry `q_logic · bracket`.
///
/// Both rows come from [`LogicRow::read`], so the selectors and the seven wire
/// values are the ones the gadget emits — including `q_logic`, which the two
/// selectors set to `-1` and `1`.
///
/// Both arms are kept, and neither is redundant — though not for the reason the
/// roots suggest. The residual is the same cubic under both selectors (see
/// [`FORGED_ROUND`]), so the AND arm reaches no root structure the XOR arm
/// misses. What it pins is the pairing: the residual only collapses that way
/// while `q_c = 1` goes with `d = a & b` and `q_c = -1` with `d = a ^ b`, so a
/// gadget that crossed them would fail the `delta_xor_and` assertion on the AND
/// row. The XOR arm carries the other axis: it is the only one that catches
/// `q_logic` being dropped from the prover's two copies, since `q_logic = 1` on
/// the AND row collapses `binding_term` onto `bracket`.
#[test]
fn forged_product_wire_reduces_the_logic_identity_to_its_binding_term() {
    let evaluation = |value: BlsScalar| {
        Evaluations::from_vec_and_domain(
            Vec::from([value]),
            EvaluationDomain::new(1).expect("a one-element domain"),
        )
    };
    let constant = |value: BlsScalar| {
        Polynomial::from_coefficients_vec(Vec::from([value]))
    };

    // Distinct, so the assertion on the returned points can tell which of the
    // widget's two commitments it pushed.
    let q_c_commitment = Commitment::from(G1Affine::generator());
    let q_logic_commitment =
        Commitment::from(G1Affine::from(G1Projective::generator().double()));
    assert_ne!(
        q_c_commitment, q_logic_commitment,
        "the two synthetic commitments must differ",
    );

    // Arbitrary, beyond being nonzero with pairwise-distinct squares: five
    // distinct `κ` are what force all five coefficients of the identity.
    let challenges = [
        BlsScalar::from(0x8d1f_2b07u64),
        BlsScalar::from(0x41c6_9e35u64),
        BlsScalar::from(0xb703_5ad9u64),
        BlsScalar::from(0x2ef8_11a4u64),
        BlsScalar::from(0x6a94_c3e2u64),
    ];
    for (i, challenge) in challenges.iter().enumerate() {
        assert_ne!(*challenge, BlsScalar::zero(), "challenge {i} is zero");
        for other in &challenges[i + 1..] {
            assert_ne!(
                challenge.square(),
                other.square(),
                "the challenges must weight the residuals differently",
            );
        }
    }

    for (label, and) in [("xor", false), ("and", true)] {
        let honest_row = LogicRow::read(
            &ForgeCircuit {
                and,
                ..Default::default()
            },
            FORGED_ROUND,
        );
        let forged_row = LogicRow::read(
            &ForgeCircuit {
                and,
                forged_wire: Some((FORGED_ROUND, BlsScalar::from(FORGED_WIRE))),
                ..Default::default()
            },
            FORGED_ROUND,
        );

        // Forging the wire must leave everything else on the row alone, or the
        // reduction below would be pinning a different row than the one the
        // honest gadget emits.
        let (a, b, d) = honest_row.quads();
        assert_eq!(
            forged_row.quads(),
            (a, b, d),
            "{label}: forging the wire must not move the quads",
        );
        assert_eq!(forged_row.q_c, honest_row.q_c, "{label}: `q_c` moved");
        assert_eq!(
            forged_row.q_logic, honest_row.q_logic,
            "{label}: `q_logic` moved",
        );
        assert_ne!(
            honest_row.q_logic,
            BlsScalar::zero(),
            "{label}: a zero `q_logic` would satisfy the reduction vacuously",
        );
        assert_eq!(
            (a, b),
            (BlsScalar::from(1u64), BlsScalar::from(2u64)),
            "{label}: the forged round must carry a quad pair whose product \
             wire has a second root over the field; see `FORGED_ROUND`",
        );
        assert_eq!(
            honest_row.c_eval,
            a * b,
            "{label}: the honest wire is the quad product",
        );
        assert_ne!(
            forged_row.c_eval, honest_row.c_eval,
            "{label}: the forged wire must differ from the honest one",
        );

        // The forgery exists because the widget's own residual vanishes at both
        // wires. Asserted against `delta_xor_and` rather than re-derived, so a
        // change to it invalidates the construction instead of quietly making
        // these tests vacuous.
        for (case, row) in
            [("honest wire", &honest_row), ("forged wire", &forged_row)]
        {
            assert_eq!(
                delta_xor_and(&a, &b, &row.c_eval, &d, &row.q_c),
                BlsScalar::zero(),
                "{label}/{case}: the wire must satisfy `c_4`, or the rejection \
                 is not attributable to `c_3`",
            );
        }

        for (case, row) in
            [("honest wire", &honest_row), ("forged wire", &forged_row)]
        {
            for challenge in challenges {
                let kappa = challenge.square();
                // What `c_3` contributes, before the row's `q_logic` weights
                // it. The verifier folds `q_logic` into its commitment instead,
                // so this is the scalar it is expected to push.
                let bracket =
                    (row.c_eval - a * b) * kappa.square() * kappa * challenge;
                let binding_term = row.q_logic * bracket;

                // The row as the widget's three implementations of the identity
                // see it, with `q_c_i` left free so it can be perturbed.
                let identity = |q_c_i: BlsScalar| {
                    let prover_key = logic::ProverKey {
                        q_c: (constant(q_c_i), evaluation(q_c_i)),
                        q_logic: (
                            constant(row.q_logic),
                            evaluation(row.q_logic),
                        ),
                    };
                    let verifier_key = logic::VerifierKey {
                        q_c: q_c_commitment,
                        q_logic: q_logic_commitment,
                    };
                    let evaluations = ProofEvaluations {
                        a_eval: row.a_eval,
                        a_w_eval: row.a_w_eval,
                        b_eval: row.b_eval,
                        b_w_eval: row.b_w_eval,
                        c_eval: row.c_eval,
                        d_eval: row.d_eval,
                        d_w_eval: row.d_w_eval,
                        q_c_eval: q_c_i,
                        ..Default::default()
                    };

                    let mut scalars = Vec::new();
                    let mut points = Vec::new();
                    verifier_key.compute_linearization_commitment(
                        &challenge,
                        &mut scalars,
                        &mut points,
                        &evaluations,
                    );

                    (
                        prover_key.compute_quotient_i(
                            0,
                            &challenge,
                            &row.a_eval,
                            &row.a_w_eval,
                            &row.b_eval,
                            &row.b_w_eval,
                            &row.c_eval,
                            &row.d_eval,
                            &row.d_w_eval,
                        ),
                        prover_key
                            .compute_linearization(&challenge, &evaluations),
                        scalars,
                        points,
                    )
                };

                let (quotient, linearization, scalars, points) =
                    identity(row.q_c);
                assert_eq!(
                    quotient, binding_term,
                    "{label}/{case}: the widget's identity must reduce to the \
                     binding term",
                );
                assert_eq!(
                    linearization,
                    constant(binding_term),
                    "{label}/{case}: the prover's linearization must carry the \
                     same binding term",
                );
                assert_eq!(
                    scalars,
                    Vec::from([bracket]),
                    "{label}/{case}: the verifier's linearization must carry \
                     the same binding term",
                );
                assert_eq!(
                    points,
                    Vec::from([q_logic_commitment.0]),
                    "{label}/{case}: the verifier must weight `q_logic`",
                );

                // `q_c` reaches the identity only through `c_4`, and its
                // coefficient there — `9d - 3(a + b)` — is nonzero on this row
                // for both selectors, so a live `c_4` has to move.
                let (quotient, linearization, scalars, _) =
                    identity(row.q_c + BlsScalar::one());
                assert_ne!(
                    quotient, binding_term,
                    "{label}/{case}: `c_4` must be alive in the quotient",
                );
                assert_ne!(
                    linearization,
                    constant(binding_term),
                    "{label}/{case}: `c_4` must be alive in the prover's \
                     linearization",
                );
                assert_ne!(
                    scalars,
                    Vec::from([bracket]),
                    "{label}/{case}: `c_4` must be alive in the verifier's \
                     linearization",
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical-truncation regression (250-bit, the Poseidon width).
//
// Binding `input = high * 2^num_bits + acc` with `high` range-checked is not,
// by itself, canonical: the field equation also admits `input + r`, i.e. an
// attacker can pick `acc' = (input + r) mod 2^num_bits` with a matching small
// `high'` that still fits the range check. `bind_truncation_split` closes that
// with the `< r` guard. This forces exactly that alias assignment and requires
// it to be rejected, pinning the guard at the logic gadget's width — the
// `component_truncate` module covers the primitive itself.
// ---------------------------------------------------------------------------

// A small input, so the wrap's `high` stays inside the 5-bit range check.
fn wrap_input() -> BlsScalar {
    BlsScalar::from(7u64)
}

// `r mod 2^250` (the low part of the modulus).
fn modulus_low_250() -> BlsScalar {
    // `r - 1` has the same high bits as `r`; its low bit is 0, so
    // `(r - 1) mod 2^250 = (r mod 2^250) - 1`.
    truncate(-BlsScalar::one(), 250) + BlsScalar::one()
}

// The non-canonical truncation `acc' = (input + r) mod 2^250 != input`.
fn wrap_acc() -> BlsScalar {
    truncate(wrap_input() + modulus_low_250(), 250)
}

// The matching `high' = (input - acc') / 2^250`, which makes
// `high' * 2^250 + acc' == input` in the field.
fn wrap_high() -> BlsScalar {
    let pow = BlsScalar::pow_of_2(250);
    (wrap_input() - wrap_acc()) * pow.invert().expect("2^250 is invertible")
}

#[derive(Default)]
struct WrapCircuit {
    wrap: bool,
}

impl Circuit for WrapCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        const BIT_PAIRS: usize = 125; // 250-bit truncation
        const NUM_BITS: usize = 250;
        const HIGH_BITS: usize = 255 - NUM_BITS;

        let a = composer.append_witness(wrap_input());
        composer.assert_equal_constant(a, wrap_input(), None);

        let result = if self.wrap {
            // Forge the loop with the wrap accumulator, then attach the SAME
            // binding gates as the honest gadget, but force `high` to the wrap
            // value `high'` (the honest gadget would derive `high = 0` from
            // `a`).
            let (d, left_acc_wit, right_acc_wit) = forge_logic_loop::<BIT_PAIRS>(
                composer,
                Composer::ZERO,
                wrap_acc(),
                None,
                true,
            );

            let high = composer.append_witness(wrap_high());
            composer.range_check(high, HIGH_BITS);
            let pow = BlsScalar::pow_of_2(NUM_BITS as u64);
            let recomposed = composer.gate_add(
                Constraint::new().left(pow).right(1).a(high).b(left_acc_wit),
            );
            composer.assert_equal(recomposed, a);

            // Emit the canonical `< r` guard on the forged split too, so this
            // branch reproduces the honest gadget's exact gate layout (and so
            // its verifier key). The wrap accumulator recomposes to the integer
            // `input + r`, i.e. a value `>= r`, which is precisely what the
            // guard rejects: `(high', acc')` exceeds `(r_high, r_low)`
            // lexicographically, so one of the guard's range checks underflows
            // and the assignment is unsatisfiable. The rejection is therefore
            // the guard constraint firing — not a circuit-size mismatch — which
            // is what pins the guard's soundness at the logic-gadget width.
            composer.assert_canonical_truncation(high, left_acc_wit, NUM_BITS);

            // `b = 0` is bound honestly.
            composer.bind_truncated_input::<BIT_PAIRS>(
                Composer::ZERO,
                right_acc_wit,
            );

            d
        } else {
            composer.append_logic_xor::<BIT_PAIRS>(a, Composer::ZERO)
        };

        let claimed = if self.wrap {
            wrap_acc()
        } else {
            truncate(wrap_input(), 250)
        };
        let public = composer.append_public(claimed);
        composer.assert_equal(result, public);

        Ok(())
    }
}

#[test]
fn logic_xor_truncation_is_canonical() {
    // Sanity on the wrap construction. It has to be a genuine forgery that
    // clears every constraint except the canonical guard, so that the guard is
    // the only thing that can reject it.
    let honest_low = truncate(wrap_input(), 250);
    assert_ne!(
        wrap_acc(),
        honest_low,
        "wrap accumulator must differ from honest"
    );
    assert!(
        fits(wrap_acc(), 250),
        "acc' must be < 2^250, the bound the logic gate imposes on it",
    );
    assert!(
        fits(wrap_high(), 5),
        "high' must clear the 5-bit range check"
    );
    assert_eq!(
        wrap_high() * BlsScalar::pow_of_2(250) + wrap_acc(),
        wrap_input(),
        "the wrap split must recompose to the input in-field",
    );

    let mut rng = StdRng::seed_from_u64(0x10_91d);
    let pp =
        PublicParameters::setup(1 << 12, &mut rng).expect("public parameters");
    let (prover, verifier): (Prover, Verifier) =
        Compiler::compile::<WrapCircuit>(&pp, b"logic-gate-wrap")
            .expect("compile");

    // Control: honest prover verifies.
    let honest = WrapCircuit { wrap: false };
    assert_eq!(
        assert_verifies(&prover, &verifier, &mut rng, &honest),
        vec![honest_low],
    );

    // The `+ r` alias must not yield a verifying proof. It clears both range
    // checks and the linear binding, so the canonical guard is the only
    // constraint left to reject it.
    assert_rejected(
        &prover,
        &mut rng,
        &honest,
        &WrapCircuit { wrap: true },
        "non-canonical (+r) truncation",
    );
}

// Pins the *production* binding structurally, without a proving round-trip: it
// fails the moment the real gadget stops wiring its inputs into a gate. The
// forge tests above catch the same regression — they attach their own copy of
// `bind_logic_accumulators`, so dropping the production call makes the honest
// circuit shrink and `assert_rejected`'s layout comparison fire — but this one
// says so directly and in a fraction of the time.
#[test]
fn append_logic_xor_wires_its_inputs() {
    const BIT_PAIRS: usize = 125; // 250-bit truncation, the Poseidon width

    let mut composer = Composer::initialized();
    let a = composer.append_witness(BlsScalar::from(0x0f0f_0ff0_u64));
    let b = composer.append_witness(BlsScalar::from(0xffff_0000_u64));

    let _ = composer.append_logic_xor::<BIT_PAIRS>(a, b);

    let mut a_wired = false;
    let mut b_wired = false;
    for gate in &composer.constraints {
        for wire in [gate.a, gate.b, gate.c, gate.d] {
            a_wired |= wire.index() == a.index();
            b_wired |= wire.index() == b.index();
        }
    }

    assert!(
        a_wired,
        "append_logic_xor must wire input `a` into a gate (output binding)",
    );
    assert!(
        b_wired,
        "append_logic_xor must wire input `b` into a gate (output binding)",
    );
}

/// Pins the gadget's emitted gate layout on its own.
///
/// The forgery tests hand-copy the gadget's emission into
/// [`forge_logic_loop`], and `assert_rejected` only compares the two against
/// each other — an edit applied to both stays green while the layout the gadget
/// emits, and every verifier key built on it, moves underneath. This is the
/// assertion that does not compare the gadget to a copy of itself.
///
/// Captured at `BIT_PAIRS = 125` (250 bits), not at the `BIT_PAIRS = 16` the
/// forgery tests above use. 250 is the width the gadget is actually compiled at
/// by its callers: `dusk-poseidon`'s hash gadget truncates each of its outputs
/// through `append_logic_xor::<125>(_, ZERO)`, which is the shape reproduced
/// here. A golden at a width nobody downstream compiles would pin nothing
/// anyone ships.
///
/// **This is a drift pin, not yet a compatibility pin.** The gates binding the
/// gadget's accumulators to its inputs are unreleased — `v0.22.1` carries no
/// such binding at all — and they changed the layout, and so the verifier key,
/// of every caller. The digests below therefore stand for no deployed key; they
/// become a compatibility pin at the release that ships the binding. The
/// `BIT_PAIRS <= 127` cap is not part of that despite landing in the same
/// window: it is a `const` assertion that emits no gate, and `v0.22.1` derived
/// the same quad count at every width the cap still admits. The suite's other
/// goldens are a mix of the two kinds — which one a golden is depends on
/// whether the gadget it was captured from has shipped, so read each one's own
/// note rather than assuming.
///
/// Both entry points are pinned. They share the emission body, so a drift there
/// moves both digests and either would catch it; the second is what catches a
/// change to `Constraint::logic`'s selector values alone, which the XOR digest
/// never sees.
///
/// The layout does not depend on the witness values — nothing in the emission
/// or in its closing truncation binding branches on one, which is also what
/// lets [`assert_rejected`] compare an honest circuit against a forged one.
#[test]
fn append_logic_component_layout_matches_golden() {
    // `gate_digest`s captured from the gadget as it stands with the unreleased
    // width cap and input-binding gates.
    const GOLDEN_XOR: [u8; 32] = [
        32, 161, 124, 154, 171, 19, 190, 198, 173, 78, 161, 187, 34, 114, 227,
        147, 171, 13, 126, 114, 18, 25, 221, 142, 1, 219, 8, 111, 203, 199,
        216, 57,
    ];
    const GOLDEN_AND: [u8; 32] = [
        155, 86, 135, 38, 200, 186, 164, 136, 179, 4, 230, 133, 119, 57, 60,
        185, 191, 172, 130, 234, 223, 96, 62, 50, 62, 203, 224, 5, 39, 207,
        143, 32,
    ];

    macro_rules! assert_golden_eq {
        ($entry:ident, $expected:expr) => {{
            let mut composer = Composer::initialized();
            let input = composer.append_witness(-BlsScalar::one());
            composer.$entry::<125>(input, Composer::ZERO);
            assert_eq!(
                gate_digest(&composer.constraints),
                $expected,
                concat!(
                    stringify!($entry),
                    "::<125>'s gate layout drifted from the pinned one",
                ),
            );
        }};
    }

    assert_golden_eq!(append_logic_xor, GOLDEN_XOR);
    assert_golden_eq!(append_logic_and, GOLDEN_AND);
}
