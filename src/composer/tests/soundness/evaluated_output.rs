// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regressions for `append_evaluated_output`.
//!
//! The helper used to evaluate its polynomial from host witness values and
//! allocate the result without appending a gate relating that result to the
//! inputs. A shape-compatible malicious prover could replace the allocated
//! value and satisfy only its downstream uses. In particular, a circuit that
//! exposed the result publicly could prove `2 + 3 = 9`.
//!
//! These tests compile from the honest public helper and inject the forged
//! output at the same witness index into the same arithmetic row. Rejection
//! therefore comes from the output relation itself, not a gate-count or wiring
//! mismatch. Separate structural checks pin the helper and both wrappers to
//! exactly one intended arithmetic row.

use dusk_bls12_381::BlsScalar;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{assert_rejected, assert_verifies};
use crate::composer::{Circuit, Composer, Constraint, Witness};
use crate::error::Error;
use crate::prelude::{
    Compiler, PlonkVersion, Prover, PublicParameters, Verifier,
};

fn sum_constraint(a: Witness, b: Witness, output: BlsScalar) -> Constraint {
    Constraint::new().left(1).right(1).output(output).a(a).b(b)
}

#[derive(Clone)]
struct DirectOutputCircuit {
    a: BlsScalar,
    b: BlsScalar,
    claimed: BlsScalar,
    forged_output: Option<BlsScalar>,
}

impl Default for DirectOutputCircuit {
    fn default() -> Self {
        Self {
            a: BlsScalar::from(2u64),
            b: BlsScalar::from(3u64),
            claimed: BlsScalar::from(5u64),
            forged_output: None,
        }
    }
}

impl Circuit for DirectOutputCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let a = composer.append_public(self.a);
        let b = composer.append_public(self.b);
        let constraint = sum_constraint(a, b, -BlsScalar::one());

        let output = match self.forged_output {
            None => composer
                .append_evaluated_output(constraint)
                .expect("output selector is -1"),
            Some(value) => {
                // A malicious prover's assignment: preserve the production
                // witness index, selectors, and wiring, but replace the output
                // value. The new arithmetic row must reject it.
                let output = composer.append_witness(value);
                composer.append_gate(constraint.c(output));
                output
            }
        };

        let claimed = composer.append_public(self.claimed);
        composer.assert_equal(output, claimed);

        Ok(())
    }
}

fn compile_direct(pp: &PublicParameters) -> (Prover, Verifier) {
    Compiler::compile::<DirectOutputCircuit>(
        pp,
        b"append-evaluated-output-soundness-v3",
    )
    .expect("compile direct-output circuit")
}

#[test]
fn direct_output_relation_rejects_shape_compatible_substitution_under_v3() {
    assert_eq!(PlonkVersion::current(), PlonkVersion::V3);

    let mut rng = StdRng::seed_from_u64(0xe7_a1_0a_7e);
    let pp = PublicParameters::setup(1 << 5, &mut rng).expect("setup");
    let (prover, verifier) = compile_direct(&pp);

    let honest = DirectOutputCircuit::default();
    assert_eq!(
        assert_verifies(&prover, &verifier, &mut rng, &honest),
        vec![
            BlsScalar::from(2u64),
            BlsScalar::from(3u64),
            BlsScalar::from(5u64),
        ],
    );

    // Honest witness generation computes five, so merely claiming nine must
    // remain unsatisfied.
    let wrong_claim = DirectOutputCircuit {
        claimed: BlsScalar::from(9u64),
        ..honest.clone()
    };
    assert_rejected(
        &prover,
        &mut rng,
        &honest,
        &wrong_claim,
        "honest output five cannot be claimed as nine",
    );

    // The historical exploit replaces the helper's output witness with nine.
    // The forged circuit emits the exact fixed layout and is rejected by the
    // newly appended arithmetic relation.
    let substituted = DirectOutputCircuit {
        claimed: BlsScalar::from(9u64),
        forged_output: Some(BlsScalar::from(9u64)),
        ..honest.clone()
    };
    assert_rejected(
        &prover,
        &mut rng,
        &honest,
        &substituted,
        "shape-compatible 2 + 3 = 9 substitution",
    );
}

fn assert_helper_row(
    a_value: BlsScalar,
    b_value: BlsScalar,
    left: BlsScalar,
    right: BlsScalar,
    output_selector: BlsScalar,
    expected_output: Option<BlsScalar>,
) {
    let mut composer = Composer::initialized();
    let a = composer.append_witness(a_value);
    let b = composer.append_witness(b_value);
    let constraints_before = composer.constraints.len();
    let witnesses_before = composer.witnesses.len();

    let constraint = Constraint::new()
        .left(left)
        .right(right)
        .output(output_selector)
        .a(a)
        .b(b);
    let output = composer.append_evaluated_output(constraint);

    assert_eq!(
        composer.constraints.len(),
        constraints_before + 1,
        "the helper must append exactly one row",
    );
    let gate = composer.constraints.last().expect("appended row");
    assert_eq!(gate.q_arith, BlsScalar::one());
    assert_eq!(gate.q_range, BlsScalar::zero());
    assert_eq!(gate.q_logic, BlsScalar::zero());
    assert_eq!(gate.q_fixed_group_add, BlsScalar::zero());
    assert_eq!(gate.q_variable_group_add, BlsScalar::zero());
    assert_eq!(gate.q_l, left);
    assert_eq!(gate.q_r, right);
    assert_eq!(gate.q_o, output_selector);
    assert_eq!(gate.a, a);
    assert_eq!(gate.b, b);

    match (output, expected_output) {
        (Some(output), Some(expected)) => {
            assert_eq!(composer.witnesses.len(), witnesses_before + 1);
            assert_eq!(composer[output], expected);
            assert_eq!(gate.c, output);
        }
        (None, None) => {
            assert_eq!(composer.witnesses.len(), witnesses_before);
            assert_eq!(gate.c, Composer::ZERO);
        }
        _ => panic!("output presence did not match selector invertibility"),
    }
}

#[test]
fn helper_appends_one_row_for_every_output_selector_class() {
    let two = BlsScalar::from(2u64);
    let three = BlsScalar::from(3u64);
    let five = BlsScalar::from(5u64);

    // q_O = 1: c = -(2 + 3).
    assert_helper_row(
        two,
        three,
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        Some(-five),
    );

    // q_O = -1: c = 2 + 3.
    assert_helper_row(
        two,
        three,
        BlsScalar::one(),
        BlsScalar::one(),
        -BlsScalar::one(),
        Some(five),
    );

    // A nontrivial invertible q_O: c = -(2 + 3) / 2.
    let inverse_two = two.invert().expect("two is invertible");
    assert_helper_row(
        two,
        three,
        BlsScalar::one(),
        BlsScalar::one(),
        two,
        Some(-five * inverse_two),
    );

    // q_O = 0: no output is allocated, but the satisfied polynomial
    // 2 - 2 = 0 is still appended as an active arithmetic row.
    assert_helper_row(
        two,
        two,
        BlsScalar::one(),
        -BlsScalar::one(),
        BlsScalar::zero(),
        None,
    );
}

#[test]
fn wrappers_each_append_exactly_one_arithmetic_row() {
    let mut add = Composer::initialized();
    let add_a = add.append_witness(BlsScalar::from(2u64));
    let add_b = add.append_witness(BlsScalar::from(3u64));
    let add_before = add.constraints.len();
    let add_output =
        add.gate_add(Constraint::new().left(1).right(1).a(add_a).b(add_b));
    assert_eq!(add.constraints.len(), add_before + 1);
    let add_gate = add.constraints.last().expect("addition row");
    assert_eq!(add_gate.q_arith, BlsScalar::one());
    assert_eq!(add_gate.q_l, BlsScalar::one());
    assert_eq!(add_gate.q_r, BlsScalar::one());
    assert_eq!(add_gate.q_o, -BlsScalar::one());
    assert_eq!(add_gate.c, add_output);
    assert_eq!(add[add_output], BlsScalar::from(5u64));

    let mut mul = Composer::initialized();
    let mul_a = mul.append_witness(BlsScalar::from(2u64));
    let mul_b = mul.append_witness(BlsScalar::from(3u64));
    let mul_before = mul.constraints.len();
    let mul_output = mul.gate_mul(Constraint::new().mult(1).a(mul_a).b(mul_b));
    assert_eq!(mul.constraints.len(), mul_before + 1);
    let mul_gate = mul.constraints.last().expect("multiplication row");
    assert_eq!(mul_gate.q_arith, BlsScalar::one());
    assert_eq!(mul_gate.q_m, BlsScalar::one());
    assert_eq!(mul_gate.q_o, -BlsScalar::one());
    assert_eq!(mul_gate.c, mul_output);
    assert_eq!(mul[mul_output], BlsScalar::from(6u64));
}
