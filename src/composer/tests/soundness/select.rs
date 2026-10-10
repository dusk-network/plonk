// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regressions for the selection gadgets. Every gate they emit
//! binds one step of the selection, so an assignment that violates any single
//! one of them must be rejected.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{assert_rejected, assert_verifies};
use crate::composer::{Composer, Constraint, Witness};
use crate::prelude::{Circuit, Compiler, Error, PublicParameters};

#[derive(Clone, Copy, Default)]
enum Gadget {
    #[default]
    Select,
    SelectOne,
    SelectZero,
}

/// A selection on `bit = 1` between `a = 3` and `b = 5`, either honest or
/// with the gadget's gates emitted over forged values of their outputs.
#[derive(Default)]
struct Selection {
    gadget: Gadget,
    forged: Option<Vec<BlsScalar>>,
}

impl Circuit for Selection {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let bit = composer.append_witness(BlsScalar::one());
        let a = composer.append_witness(BlsScalar::from(3u64));
        let b = composer.append_witness(BlsScalar::from(5u64));

        match (&self.forged, self.gadget) {
            (None, Gadget::Select) => {
                composer.component_select(bit, a, b);
            }
            (None, Gadget::SelectOne) => {
                composer.component_select_one(bit, a);
            }
            (None, Gadget::SelectZero) => {
                composer.component_select_zero(bit, a);
            }
            (Some(values), gadget) => {
                forge(composer, gadget, values, bit, a, b)
            }
        }

        Ok(())
    }
}

/// Emit the gates of `gadget` gate for gate, with `values` as the witnesses of
/// their outputs, in emission order.
fn forge(
    composer: &mut Composer,
    gadget: Gadget,
    values: &[BlsScalar],
    bit: Witness,
    a: Witness,
    b: Witness,
) {
    let outputs: Vec<Witness> =
        values.iter().map(|v| composer.append_witness(*v)).collect();
    let minus_one = -BlsScalar::one();

    let gates = match gadget {
        Gadget::Select => [
            // bit * a
            Constraint::new().mult(1).a(bit).b(a),
            // 1 - bit
            Constraint::new().left(minus_one).constant(1).a(bit),
            // (1 - bit) * b
            Constraint::new().mult(1).a(outputs[1]).b(b),
            // (1 - bit) * b + bit * a
            Constraint::new()
                .left(1)
                .right(1)
                .a(outputs[2])
                .b(outputs[0]),
        ]
        .to_vec(),
        // 1 - bit + bit * a
        Gadget::SelectOne => [Constraint::new()
            .mult(1)
            .left(minus_one)
            .constant(1)
            .a(bit)
            .b(a)]
        .to_vec(),
        // bit * a
        Gadget::SelectZero => [Constraint::new().mult(1).a(bit).b(a)].to_vec(),
    };

    gates.into_iter().zip(outputs).for_each(|(gate, output)| {
        composer.append_gate(gate.output(minus_one).c(output))
    });
}

/// Proves the honest selection of `gadget` and rejects each forged
/// assignment of its gate outputs.
fn assert_forgeries_rejected(gadget: Gadget, forgeries: &[(&str, &[u64])]) {
    let mut rng = StdRng::seed_from_u64(0x5e1ec7);
    let pp = PublicParameters::setup(1 << 5, &mut rng).expect("setup");
    let honest = Selection {
        gadget,
        forged: None,
    };
    let (prover, verifier) =
        Compiler::compile_with_circuit(&pp, b"select", &honest)
            .expect("compile");
    assert_verifies(&prover, &verifier, &mut rng, &honest);

    for (case, values) in forgeries {
        let forged = Selection {
            gadget,
            forged: Some(values.iter().map(|v| BlsScalar::from(*v)).collect()),
        };
        assert_rejected(&prover, &mut rng, &honest, &forged, case);
    }
}

#[test]
fn select_rejects_a_forged_gate_output() {
    // The honest outputs are `bit * a = 3`, `1 - bit = 0`, `(1 - bit) * b =
    // 0` and the selection `3`. Each forgery breaks exactly one gate and keeps
    // the others satisfied; the last two select `b`.
    assert_forgeries_rejected(
        Gadget::Select,
        &[
            ("bit * a", &[0, 0, 0, 0]),
            ("1 - bit", &[3, 1, 5, 8]),
            ("(1 - bit) * b", &[3, 0, 2, 5]),
            ("selection", &[3, 0, 0, 5]),
        ],
    );
}

#[test]
fn select_one_and_zero_reject_a_forged_output() {
    // `bit = 1` selects `a = 3` in both gadgets, not their constant.
    assert_forgeries_rejected(Gadget::SelectOne, &[("one", &[1])]);
    assert_forgeries_rejected(Gadget::SelectZero, &[("zero", &[0])]);
}
