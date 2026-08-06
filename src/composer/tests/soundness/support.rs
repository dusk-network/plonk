// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Shared scaffolding for the in-crate soundness regressions.
//!
//! Those tests all follow the same shape: compile a verifier key from an honest
//! gadget, then prove against it with a fork of that gadget filled with forged
//! witnesses. For such a test to have any teeth, two things have to hold, and
//! both are easy to get silently wrong:
//!
//! - the forgery must emit **exactly** the compiled gate layout, otherwise the
//!   prover rejects it on a circuit-size mismatch and the test passes without
//!   ever reaching the constraint it claims to exercise;
//! - the rejection must come from an **unsatisfied constraint** specifically,
//!   not from any error the prover happens to return.
//!
//! [`gate_layout`] and [`assert_rejected`] pin those down.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubAffine, JubJubScalar};
use rand::rngs::StdRng;

use crate::composer::bits::recompose_bits;
use crate::composer::{Circuit, Composer, Gate};
use crate::error::Error;
use crate::prelude::{Prover, Verifier};

/// `2^num_bits` as a field element.
pub(super) fn pow(num_bits: usize) -> BlsScalar {
    BlsScalar::pow_of_2(num_bits as u64)
}

/// The inverse of a value the forgery constructions require to be invertible.
///
/// Those constructions solve a gadget's output check for its coordinate, and
/// the denominator is the coefficient that check carries on it. Where it
/// vanishes the check degenerates and leaves the coordinate free — a case none
/// of the forgeries mean to exercise, so this panics rather than returning a
/// value that would silently stand in for one.
pub(super) fn invert(value: BlsScalar) -> BlsScalar {
    value.invert().expect("the denominator is invertible")
}

/// The point the steering forgeries aim at.
///
/// A gadget that leaves a helper wire unbound lets a prover choose one
/// coordinate of the gadget's claimed output. Aiming that choice at a real
/// curve point, rather than at an arbitrary field element, makes the stolen
/// coordinate one that could legitimately have arisen — so a rejection cannot
/// be attributed to the claim being obviously malformed.
pub(super) fn steering_target() -> JubJubAffine {
    JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::from(7u64))
}

/// Truncation of `x` to its low `num_bits` bits, as a field element.
pub(super) fn truncate(x: BlsScalar, num_bits: usize) -> BlsScalar {
    recompose_bits(&x.to_bits(), 0, num_bits)
}

/// Whether `x` lies in `[0, 2^num_bits)`, i.e. whether it would clear a
/// `range_check` of that width. Used to pin down *which* constraint rejects a
/// forgery: one meant to be caught by the canonical guard must clear every
/// range check first.
pub(super) fn fits(x: BlsScalar, num_bits: usize) -> bool {
    truncate(x, num_bits) == x
}

/// The gate layout (selectors AND wiring) a circuit emits. [`Gate`] is
/// `PartialEq`, so comparing these vectors compares the whole constraint
/// system, which is what the compiled verifier key is derived from.
pub(super) fn gate_layout<C: Circuit>(circuit: &C) -> Vec<Gate> {
    let mut composer = Composer::initialized();
    circuit.circuit(&mut composer).expect("circuit builds");
    composer.constraints
}

/// Fold a gate vector (selectors AND wiring) into a single field element: a
/// deterministic, platform-independent fingerprint of the full gate layout.
/// Field arithmetic is exact, so the digest is reproducible across machines and
/// builds; any change to a selector or a wire index changes it. This is a
/// layout fingerprint, not a cryptographic hash — collisions are irrelevant
/// because the inputs are not adversarial, only accidentally-drifting layouts.
///
/// `Gate` is destructured exhaustively on purpose: the golden test leans on the
/// converse of the digest's contract — an unchanged digest meaning an unchanged
/// verifier key — which only holds while every field is folded in. A field
/// added to `Gate` must fail to compile here, not silently drop out.
pub(super) fn gate_digest(gates: &[Gate]) -> [u8; 32] {
    let mult = BlsScalar::from(1_000_003u64);
    let mut acc = BlsScalar::zero();
    for gate in gates {
        let Gate {
            q_m,
            q_l,
            q_r,
            q_o,
            q_f,
            q_c,
            q_arith,
            q_range,
            q_logic,
            q_fixed_group_add,
            q_variable_group_add,
            a,
            b,
            c,
            d,
        } = gate;

        for selector in [
            q_m,
            q_l,
            q_r,
            q_o,
            q_f,
            q_c,
            q_arith,
            q_range,
            q_logic,
            q_fixed_group_add,
            q_variable_group_add,
        ] {
            acc = acc * mult + selector;
        }
        for wire in [a, b, c, d] {
            acc = acc * mult + BlsScalar::from(wire.index() as u64);
        }
    }
    acc.to_bytes()
}

/// Prove `honest` and verify the resulting proof, returning its public inputs.
pub(super) fn assert_verifies<C: Circuit>(
    prover: &Prover,
    verifier: &Verifier,
    rng: &mut StdRng,
    honest: &C,
) -> Vec<BlsScalar> {
    let (proof, public_inputs) =
        prover.prove(rng, honest).expect("honest prove");
    verifier
        .verify(&proof, &public_inputs)
        .expect("honest proof must verify");

    public_inputs
}

/// Require `rejected` to emit the same gate layout as `accepted` and then to be
/// turned away at proving by an unsatisfied constraint.
///
/// Both halves matter. Without the layout check, dropping a constraint from the
/// production gadget would leave the rejected circuit emitting a gate the
/// accepted one no longer does, and the resulting `InvalidCircuitSize` would
/// read as a successful rejection. Without the error check, any unrelated
/// proving failure would do the same.
///
/// The control proof (the accepted circuit proving against the same commit
/// key on an identical gate layout) is what makes [`Error::CircuitUnsatisfied`]
/// conclusive here: the only thing that can differ between the accepted and
/// rejected circuit is satisfiability.
pub(super) fn assert_rejected<C: Circuit>(
    prover: &Prover,
    rng: &mut StdRng,
    accepted: &C,
    rejected: &C,
    case: &str,
) {
    assert_eq!(
        gate_layout(rejected),
        gate_layout(accepted),
        "{case}: must emit the same gate layout as the accepted circuit, else \
         its rejection says nothing about the constraint under test",
    );

    match prover.prove(rng, rejected) {
        Ok(_) => panic!("{case}: produced a proof"),
        Err(Error::CircuitUnsatisfied) => {}
        Err(other) => panic!(
            "{case}: rejected by `{other:?}`, not by an unsatisfied \
             constraint — it is not exercising the constraint under test",
        ),
    }
}
