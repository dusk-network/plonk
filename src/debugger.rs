// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Debugger module

use std::env;
use std::path::PathBuf;

use dusk_bls12_381::BlsScalar;
use dusk_cdf::{
    BaseConfig, Config, EncodableConstraint, EncodableSource, EncodableWitness,
    Encoder, EncoderContextFileProvider, Polynomial, Selectors, WiredWitnesses,
};
use dusk_jubjub::EDWARDS_D;

use crate::composer::{Constraint, Selector, WiredWitness, Witness};
use crate::proof_system::widget::ecc::scalar_mul::fixed_base::proverkey::{
    check_bit_consistency, extract_bit,
};
use crate::proof_system::widget::logic::proverkey::{
    delta as logic_delta, delta_xor_and,
};
use crate::proof_system::widget::range::proverkey::delta as range_delta;
use crate::runtime::RuntimeEvent;

/// Gate-identity family names, index-aligned with the array returned by
/// [`Debugger::identity_evaluations`].
const IDENTITY_FAMILIES: [&str; 17] = [
    "arithmetic",
    "range delta c/d",
    "range delta b/c",
    "range delta a/b",
    "range accumulator",
    "logic left quad",
    "logic right quad",
    "logic output quad",
    "logic product",
    "logic relation",
    "fixed-base bit consistency",
    "fixed-base xy consistency",
    "fixed-base x accumulator",
    "fixed-base y accumulator",
    "variable-base xy consistency",
    "variable-base x accumulator",
    "variable-base y accumulator",
];

/// PLONK debugger
#[derive(Debug, Clone)]
pub(crate) struct Debugger {
    witnesses: Vec<(EncodableSource, Witness, BlsScalar)>,
    constraints: Vec<(EncodableSource, Constraint)>,
}

impl Debugger {
    fn witness_value(&self, witness: Witness) -> BlsScalar {
        self.witnesses
            .get(witness.index())
            .map(|(_, _, value)| *value)
            .unwrap_or_default()
    }

    fn wire_value(
        &self,
        constraint: &Constraint,
        wire: WiredWitness,
    ) -> BlsScalar {
        self.witness_value(constraint.witness(wire))
    }

    /// The wire of the row the prover's rotated (`_w`) evaluation reads.
    ///
    /// The prover interpolates over a cyclic domain of the padded circuit
    /// size, so the last row's rotation wraps to row 0. Padding rows carry
    /// zero wires, which is what a miss on `constraints` yields — but when
    /// the gate count is already a power of two there is no padding, and the
    /// wrap lands on a live constraint instead.
    fn shifted_wire_value(
        &self,
        constraint_index: usize,
        wire: WiredWitness,
    ) -> BlsScalar {
        let padded_size = self.constraints.len().next_power_of_two();
        let shifted = (constraint_index + 1) % padded_size;

        self.constraints
            .get(shifted)
            .map(|(_, constraint)| self.wire_value(constraint, wire))
            .unwrap_or_default()
    }

    fn identity_evaluations(
        &self,
        constraint_index: usize,
        constraint: &Constraint,
    ) -> [BlsScalar; IDENTITY_FAMILIES.len()] {
        let qm = *constraint.coeff(Selector::Multiplication);
        let ql = *constraint.coeff(Selector::Left);
        let qr = *constraint.coeff(Selector::Right);
        let qo = *constraint.coeff(Selector::Output);
        let qf = *constraint.coeff(Selector::Fourth);
        let qc = *constraint.coeff(Selector::Constant);
        let pi = *constraint.coeff(Selector::PublicInput);
        let qarith = *constraint.coeff(Selector::Arithmetic);
        let qlogic = *constraint.coeff(Selector::Logic);
        let qrange = *constraint.coeff(Selector::Range);
        let qgroup_variable = *constraint.coeff(Selector::GroupAddVariableBase);
        let qfixed_add = *constraint.coeff(Selector::GroupAddFixedBase);

        let a = self.wire_value(constraint, WiredWitness::A);
        let b = self.wire_value(constraint, WiredWitness::B);
        let c = self.wire_value(constraint, WiredWitness::C);
        let d = self.wire_value(constraint, WiredWitness::D);
        let a_w = self.shifted_wire_value(constraint_index, WiredWitness::A);
        let b_w = self.shifted_wire_value(constraint_index, WiredWitness::B);
        let d_w = self.shifted_wire_value(constraint_index, WiredWitness::D);

        let arithmetic =
            (qm * a * b + ql * a + qr * b + qo * c + qf * d + qc) * qarith + pi;

        let four = BlsScalar::from(4u64);
        let range_identities = [
            range_delta(c - four * d),
            range_delta(b - four * c),
            range_delta(a - four * b),
            range_delta(d_w - four * a),
        ];

        let left_quad = a_w - four * a;
        let right_quad = b_w - four * b;
        let output_quad = d_w - four * d;
        let logic_identities = [
            logic_delta(left_quad),
            logic_delta(right_quad),
            logic_delta(output_quad),
            c - left_quad * right_quad,
            delta_xor_and(&left_quad, &right_quad, &c, &output_quad, &qc),
        ];

        let bit = extract_bit(&d, &d_w);
        let y_alpha = bit.square() * (qr - BlsScalar::one()) + BlsScalar::one();
        let x_alpha = ql * bit;
        let fixed_base_identities = [
            check_bit_consistency(bit),
            bit * qc - c,
            a_w + a_w * c * a * b * EDWARDS_D - (a * y_alpha + b * x_alpha),
            b_w - b_w * c * a * b * EDWARDS_D - (b * y_alpha + a * x_alpha),
        ];

        let x1_y2 = d_w;
        let y1_x2 = b * c;
        let variable_base_identities = [
            a * d - x1_y2,
            x1_y2 + y1_x2 - (a_w + a_w * EDWARDS_D * x1_y2 * y1_x2),
            b * d + a * c - (b_w - b_w * EDWARDS_D * x1_y2 * y1_x2),
        ];

        [
            arithmetic,
            range_identities[0] * qrange,
            range_identities[1] * qrange,
            range_identities[2] * qrange,
            range_identities[3] * qrange,
            logic_identities[0] * qlogic,
            logic_identities[1] * qlogic,
            logic_identities[2] * qlogic,
            logic_identities[3] * qlogic,
            logic_identities[4] * qlogic,
            fixed_base_identities[0] * qfixed_add,
            fixed_base_identities[1] * qfixed_add,
            fixed_base_identities[2] * qfixed_add,
            fixed_base_identities[3] * qfixed_add,
            variable_base_identities[0] * qgroup_variable,
            variable_base_identities[1] * qgroup_variable,
            variable_base_identities[2] * qgroup_variable,
        ]
    }

    fn evaluates_to_zero(
        &self,
        constraint_index: usize,
        constraint: &Constraint,
    ) -> bool {
        self.identity_evaluations(constraint_index, constraint)
            .into_iter()
            .all(|identity| identity == BlsScalar::zero())
    }

    /// Constraints whose assignment fails a gate identity, each paired with
    /// the name of the first identity family it fails.
    fn unsatisfied_constraints(&self) -> Vec<(usize, &'static str)> {
        self.constraints
            .iter()
            .enumerate()
            .filter_map(|(index, (_, constraint))| {
                self.identity_evaluations(index, constraint)
                    .into_iter()
                    .position(|identity| identity != BlsScalar::zero())
                    .map(|identity| (index, IDENTITY_FAMILIES[identity]))
            })
            .collect()
    }

    /// The diagnostic naming the first unsatisfied constraint, if any.
    /// Proving destroys the which-constraint information before it fails, so
    /// this is the only place a failing gate can be named.
    ///
    /// The check covers the prove-time assignment against its own
    /// constraints; the compiled circuit description's selectors are not
    /// available here. When the two disagree — same gate count, different
    /// selector values — proving still fails with an unsatisfied-circuit
    /// error while this report stays silent, so a silent report next to that
    /// error points at a description/assignment mismatch. The mirror also
    /// holds: a row vacuous in the description but live at prove time is
    /// named here while the proof goes through — the report catching a
    /// constraint missing from the verifier key — which is why the report
    /// must not be gated on proving having failed.
    fn unsatisfied_report(&self) -> Option<String> {
        let unsatisfied = self.unsatisfied_constraints();
        let (index, family) = unsatisfied.first()?;
        let source = &self.constraints[*index].0;

        Some(format!(
            "plonk debugger: {} of {} constraints are unsatisfied; the \
             first, constraint {index}, fails the {family} identity and was \
             appended at {}:{}:{}",
            unsatisfied.len(),
            self.constraints.len(),
            source.path(),
            source.line(),
            source.col(),
        ))
    }

    fn report_unsatisfied(&self) {
        if let Some(report) = self.unsatisfied_report() {
            eprintln!("{report}");
        }
    }

    /// Resolver the caller function
    fn resolve_caller() -> EncodableSource {
        let mut source = None;

        backtrace::trace(|frame| {
            // Resolve this instruction pointer to a symbol name
            backtrace::resolve_frame(frame, |symbol| {
                if symbol
                    .name()
                    .map(|n| n.to_string())
                    .filter(|s| !s.starts_with("backtrace::"))
                    .filter(|s| !s.starts_with("dusk_plonk::"))
                    .filter(|s| !s.starts_with("core::"))
                    .filter(|s| !s.starts_with("std::"))
                    .is_some()
                {
                    if let Some(path) = symbol.filename() {
                        let line = symbol.lineno().unwrap_or_default() as u64;
                        let col = symbol.colno().unwrap_or_default() as u64;
                        let path = path
                            .canonicalize()
                            .unwrap_or_default()
                            .display()
                            .to_string();

                        source.replace(EncodableSource::new(line, col, path));
                    }
                }
            });

            source.is_none()
        });

        source.unwrap_or_default()
    }

    fn write_output(&self) {
        let path = match env::var("CDF_OUTPUT") {
            Ok(path) => PathBuf::from(path),
            Err(env::VarError::NotPresent) => return (),
            Err(env::VarError::NotUnicode(_)) => {
                eprintln!("the provided `CDF_OUTPUT` isn't valid unicode");
                return ();
            }
        };

        let witnesses = self.witnesses.iter().map(|(source, w, value)| {
            let id = w.index();
            let value = value.to_bytes().into();
            let source = source.clone();

            EncodableWitness::new(id, None, value, source)
        });

        let constraints = self.constraints.iter().enumerate().map(
            |(id, (source, constraint))| {
                let source = source.clone();

                let qm = constraint.coeff(Selector::Multiplication);
                let ql = constraint.coeff(Selector::Left);
                let qr = constraint.coeff(Selector::Right);
                let qo = constraint.coeff(Selector::Output);
                let qf = constraint.coeff(Selector::Fourth);
                let qc = constraint.coeff(Selector::Constant);
                let pi = constraint.coeff(Selector::PublicInput);
                let qarith = constraint.coeff(Selector::Arithmetic);
                let qlogic = constraint.coeff(Selector::Logic);
                let qrange = constraint.coeff(Selector::Range);
                let qgroup_variable =
                    constraint.coeff(Selector::GroupAddVariableBase);
                let qfixed_add = constraint.coeff(Selector::GroupAddFixedBase);

                let a = constraint.witness(WiredWitness::A).index();
                let b = constraint.witness(WiredWitness::B).index();
                let c = constraint.witness(WiredWitness::C).index();
                let d = constraint.witness(WiredWitness::D).index();

                // dusk-cdf 0.5 calls PLONK's output wire `o` and its fourth
                // selector `qd`; map those schema names at this boundary.
                let witnesses = WiredWitnesses { a, b, o: c, d };

                let evaluation = self.evaluates_to_zero(id, constraint);

                let selectors = Selectors {
                    qm: qm.to_bytes().into(),
                    ql: ql.to_bytes().into(),
                    qr: qr.to_bytes().into(),
                    qo: qo.to_bytes().into(),
                    qd: qf.to_bytes().into(),
                    qc: qc.to_bytes().into(),
                    pi: pi.to_bytes().into(),
                    qarith: qarith.to_bytes().into(),
                    qlogic: qlogic.to_bytes().into(),
                    qrange: qrange.to_bytes().into(),
                    qgroup_variable: qgroup_variable.to_bytes().into(),
                    qfixed_add: qfixed_add.to_bytes().into(),
                };

                let polynomial =
                    Polynomial::new(selectors, witnesses, evaluation);

                EncodableConstraint::new(id, polynomial, source)
            },
        );

        if let Err(e) = Config::load()
            .and_then(|config| {
                Encoder::init_file(config, witnesses, constraints, &path)
            })
            .and_then(|mut c| {
                c.write_all(EncoderContextFileProvider::default())
            })
        {
            eprintln!(
                "failed to output CDF file to '{}': {}",
                path.display(),
                e
            );
        }
    }

    pub(crate) fn new() -> Self {
        Self {
            witnesses: Vec::new(),
            constraints: Vec::new(),
        }
    }

    pub(crate) fn event(&mut self, event: RuntimeEvent) {
        match event {
            RuntimeEvent::WitnessAppended { w, v } => {
                self.witnesses.push((Self::resolve_caller(), w, v));
            }

            RuntimeEvent::ConstraintAppended { c } => {
                self.constraints.push((Self::resolve_caller(), c));
            }

            RuntimeEvent::ProofFinished => {
                self.report_unsatisfied();
                self.write_output();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composer::Composer;

    fn wire_rows(constraint: Constraint, values: [BlsScalar; 8]) -> Debugger {
        let current = constraint
            .a(Witness::new(0))
            .b(Witness::new(1))
            .c(Witness::new(2))
            .d(Witness::new(3));
        let shifted = Constraint::new()
            .a(Witness::new(4))
            .b(Witness::new(5))
            .c(Witness::new(6))
            .d(Witness::new(7));

        Debugger {
            witnesses: values
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    (EncodableSource::default(), Witness::new(index), value)
                })
                .collect(),
            constraints: vec![
                (EncodableSource::default(), current),
                (EncodableSource::default(), shifted),
            ],
        }
    }

    fn assert_satisfied(
        name: &str,
        constraint: Constraint,
        values: [BlsScalar; 8],
    ) {
        let debugger = wire_rows(constraint, values);
        let constraint = &debugger.constraints[0].1;
        let identities = debugger.identity_evaluations(0, constraint);

        assert!(
            identities
                .into_iter()
                .all(|identity| identity == BlsScalar::zero()),
            "{name} fixture did not satisfy every identity: {identities:?}"
        );
        assert!(debugger.evaluates_to_zero(0, constraint));
        assert!(
            debugger.unsatisfied_constraints().is_empty(),
            "{name} fixture must report no unsatisfied constraints"
        );
    }

    fn assert_identity_fails(
        name: &str,
        identity_index: usize,
        family: &'static str,
        constraint: Constraint,
        values: [BlsScalar; 8],
    ) {
        let debugger = wire_rows(constraint, values);
        let constraint = &debugger.constraints[0].1;
        let identities = debugger.identity_evaluations(0, constraint);

        assert_ne!(
            identities[identity_index],
            BlsScalar::zero(),
            "{name} did not invalidate identity {identity_index}"
        );
        assert!(
            !debugger.evaluates_to_zero(0, constraint),
            "{name} evaluated as satisfied"
        );

        assert_eq!(
            debugger.unsatisfied_constraints(),
            vec![(0, family)],
            "{name} must be reported as the only unsatisfied constraint, \
             failing the {family} identity"
        );
    }

    fn add(
        mut values: [BlsScalar; 8],
        index: usize,
        amount: u64,
    ) -> [BlsScalar; 8] {
        values[index] += BlsScalar::from(amount);
        values
    }

    /// Witness values for the wrap fixtures: index 0 is the zero witness,
    /// 1..=4 are the last row's `a`, `b`, `c` and `d`, and index 5 is the
    /// value row 0 carries on its fourth wire.
    const WRAP_VALUES: [u64; 6] = [0, 91, 22, 5, 1, 364];

    /// A circuit of `rows` rows ending in `last`, with a nonzero fourth wire
    /// on row 0.
    ///
    /// The prover interpolates over a cyclic domain of the padded circuit
    /// size, so the last row's rotated wires read row 0 when the row count is
    /// already a power of two, and a zero padding row when it isn't.
    fn wrap_fixture(rows: usize, last: Constraint) -> Debugger {
        let mut constraints =
            vec![(EncodableSource::default(), Constraint::new()); rows - 1];
        constraints[0].1 = Constraint::new().d(Witness::new(5));
        constraints.push((EncodableSource::default(), last));

        Debugger {
            witnesses: WRAP_VALUES
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    (
                        EncodableSource::default(),
                        Witness::new(index),
                        BlsScalar::from(value),
                    )
                })
                .collect(),
            constraints,
        }
    }

    /// A range gate satisfied only when `d_w` reads row 0's fourth wire: its
    /// accumulator identity is `delta(d_w - 4a)`, and `364 - 4 * 91` is zero
    /// while `0 - 4 * 91` is not.
    fn range_row_needing_wrap() -> Constraint {
        Constraint::range(
            &Constraint::new()
                .a(Witness::new(1))
                .b(Witness::new(2))
                .c(Witness::new(3))
                .d(Witness::new(4)),
        )
    }

    // The three fixtures below assert on `evaluates_to_zero` as well as on
    // the unsatisfied-constraint report: that call is what `write_output`
    // records as the CDF `evaluation` flag, so it is the same value seen
    // from both diagnostics.

    #[test]
    fn shifted_wires_wrap_to_row_zero_on_an_exact_fill() {
        // Four rows need no padding, so the rotation wraps to row 0.
        let debugger = wrap_fixture(4, range_row_needing_wrap());
        let last = &debugger.constraints[3].1;

        assert!(
            debugger.evaluates_to_zero(3, last),
            "row 0's fourth wire satisfies the last row's range accumulator; \
             reading zero past the last row fails it"
        );
        assert!(debugger.unsatisfied_constraints().is_empty());
        assert!(debugger.unsatisfied_report().is_none());
    }

    #[test]
    fn exact_fill_wrap_catches_what_a_zero_read_would_miss() {
        // The mirror case: every wire of the last row is the zero witness, so
        // its range accumulator reduces to `delta(d_w)`. Row 0's fourth wire
        // breaks it, while reading zero past the last row would report the
        // circuit as satisfied.
        let debugger = wrap_fixture(4, Constraint::range(&Constraint::new()));
        let last = &debugger.constraints[3].1;

        assert!(!debugger.evaluates_to_zero(3, last));
        assert_eq!(
            debugger.unsatisfied_constraints(),
            vec![(3, "range accumulator")]
        );

        let report =
            debugger.unsatisfied_report().expect("row 3 is unsatisfied");
        assert!(report.contains("1 of 4 constraints"));
        assert!(report.contains("constraint 3"));
        assert!(report.contains("range accumulator identity"));
    }

    #[test]
    fn shifted_wires_past_a_padded_circuit_read_as_zero() {
        // Three rows pad to four, so the row after the last is a zero padding
        // row and the rotation must not reach back to row 0. Wrapping modulo
        // the row count rather than the padded size would satisfy this gate.
        let debugger = wrap_fixture(3, range_row_needing_wrap());
        let last = &debugger.constraints[2].1;

        assert!(!debugger.evaluates_to_zero(2, last));
        assert_eq!(
            debugger.unsatisfied_constraints(),
            vec![(2, "range accumulator")]
        );
    }

    #[test]
    fn row_zero_of_a_proving_composer_wires_only_the_zero_witness() {
        // Every proving path builds from `Composer::initialized()`, whose row
        // 0 wires all four slots to the zero witness. That is what makes the
        // wrap read the same zeros the old unconditional fallback did, so no
        // circuit reachable through the public API can tell the two apart.
        //
        // Nothing else enforces it. Pin it here rather than in the composer,
        // because this module is what depends on it: should row 0 ever carry
        // a live value, the rotated reads on an exact fill start resolving to
        // it, and the reports above change with it.
        let composer = Composer::initialized();
        let row_zero = &composer.constraints[0];

        for wire in [row_zero.a, row_zero.b, row_zero.c, row_zero.d] {
            assert_eq!(wire, Composer::ZERO);
        }
        assert_eq!(composer[Composer::ZERO], BlsScalar::zero());
    }

    #[test]
    fn unsatisfied_report_counts_and_names_the_first() {
        // With no witnesses every wire reads zero, so a gate demanding
        // constant 1 is unsatisfied on its arithmetic identity.
        let unsatisfied_gate =
            || Constraint::arithmetic(&Constraint::new().constant(1u64));
        let debugger = Debugger {
            witnesses: Vec::new(),
            constraints: vec![
                (EncodableSource::default(), unsatisfied_gate()),
                (EncodableSource::default(), unsatisfied_gate()),
            ],
        };

        let report = debugger
            .unsatisfied_report()
            .expect("both constraints are unsatisfied");
        assert!(report.contains("2 of 2 constraints"));
        assert!(report.contains("constraint 0"));
        assert!(report.contains("arithmetic identity"));

        let satisfied = Debugger {
            witnesses: Vec::new(),
            constraints: vec![(EncodableSource::default(), Constraint::new())],
        };
        assert!(satisfied.unsatisfied_report().is_none());
    }

    #[test]
    fn evaluates_all_gate_identities() {
        let arithmetic = Constraint::arithmetic(
            &Constraint::new()
                .mult(1u64)
                .left(1u64)
                .right(1u64)
                .output(1u64)
                .fourth(1u64)
                .constant(1u64)
                .public(-BlsScalar::from(6u64)),
        );
        let arithmetic_values = [BlsScalar::one(); 8];

        let range = Constraint::range(&Constraint::new());
        let range_values = [91, 22, 5, 1, 7, 8, 9, 364].map(BlsScalar::from);

        let logic_and = Constraint::logic(&Constraint::new());
        let logic_and_values = [1, 2, 3, 4, 7, 9, 5, 17].map(BlsScalar::from);

        let logic_xor = Constraint::logic_xor(&Constraint::new());
        let logic_xor_values = [1, 2, 3, 4, 7, 9, 5, 18].map(BlsScalar::from);

        let one = BlsScalar::one();
        let inverse_one_plus_d = (one + EDWARDS_D)
            .invert()
            .expect("1 + EDWARDS_D is nonzero");
        let inverse_one_minus_d = (one - EDWARDS_D)
            .invert()
            .expect("1 - EDWARDS_D is nonzero");

        let fixed_base = Constraint::group_add_fixed_base(
            &Constraint::new().right(1u64).constant(1u64),
        );
        let fixed_base_values = [
            one,
            one,
            one,
            one,
            inverse_one_plus_d,
            inverse_one_minus_d,
            one,
            BlsScalar::from(3u64),
        ];
        let variable_base =
            Constraint::group_add_variable_base(&Constraint::new());
        let variable_base_values = [
            one,
            one,
            one,
            one,
            inverse_one_plus_d.double(),
            inverse_one_minus_d.double(),
            one,
            one,
        ];

        let valid_cases = [
            ("arithmetic", arithmetic, arithmetic_values),
            ("range", range, range_values),
            ("logic AND", logic_and, logic_and_values),
            ("logic XOR", logic_xor, logic_xor_values),
            ("fixed-base addition", fixed_base, fixed_base_values),
            (
                "variable-base addition",
                variable_base,
                variable_base_values,
            ),
        ];
        for (name, constraint, values) in valid_cases {
            assert_satisfied(name, constraint, values);
        }

        let mut invalid_range_0 = range_values;
        invalid_range_0[3] = BlsScalar::zero();
        let mut invalid_range_1 = range_values;
        invalid_range_1[2] = BlsScalar::from(6u64);
        let mut invalid_range_2 = range_values;
        invalid_range_2[1] = BlsScalar::from(23u64);
        let mut invalid_range_3 = range_values;
        invalid_range_3[7] = BlsScalar::from(368u64);

        // (case name, identity index, reported family, constraint, values);
        // the family is spelled out per case so the assertion pins the
        // `IDENTITY_FAMILIES` entry independently of the array itself.
        let invalid_cases = [
            (
                "arithmetic",
                0,
                "arithmetic",
                arithmetic,
                add(arithmetic_values, 0, 1),
            ),
            (
                "range delta c/d",
                1,
                "range delta c/d",
                range,
                invalid_range_0,
            ),
            (
                "range delta b/c",
                2,
                "range delta b/c",
                range,
                invalid_range_1,
            ),
            (
                "range delta a/b",
                3,
                "range delta a/b",
                range,
                invalid_range_2,
            ),
            (
                "range accumulator",
                4,
                "range accumulator",
                range,
                invalid_range_3,
            ),
            (
                "logic left quad",
                5,
                "logic left quad",
                logic_and,
                add(logic_and_values, 4, 1),
            ),
            (
                "logic right quad",
                6,
                "logic right quad",
                logic_and,
                add(logic_and_values, 5, 3),
            ),
            (
                "logic output quad",
                7,
                "logic output quad",
                logic_and,
                add(logic_and_values, 7, 3),
            ),
            (
                "logic product",
                8,
                "logic product",
                logic_and,
                add(logic_and_values, 2, 1),
            ),
            (
                "logic AND relation",
                9,
                "logic relation",
                logic_and,
                add(logic_and_values, 7, 1),
            ),
            (
                "logic XOR relation",
                9,
                "logic relation",
                logic_xor,
                add(logic_xor_values, 7, 1),
            ),
            (
                "fixed-base bit consistency",
                10,
                "fixed-base bit consistency",
                fixed_base,
                add(fixed_base_values, 7, 1),
            ),
            (
                "fixed-base xy consistency",
                11,
                "fixed-base xy consistency",
                fixed_base,
                add(fixed_base_values, 2, 1),
            ),
            (
                "fixed-base x accumulator",
                12,
                "fixed-base x accumulator",
                fixed_base,
                add(fixed_base_values, 4, 1),
            ),
            (
                "fixed-base y accumulator",
                13,
                "fixed-base y accumulator",
                fixed_base,
                add(fixed_base_values, 5, 1),
            ),
            (
                "variable-base xy consistency",
                14,
                "variable-base xy consistency",
                variable_base,
                add(variable_base_values, 7, 1),
            ),
            (
                "variable-base x accumulator",
                15,
                "variable-base x accumulator",
                variable_base,
                add(variable_base_values, 4, 1),
            ),
            (
                "variable-base y accumulator",
                16,
                "variable-base y accumulator",
                variable_base,
                add(variable_base_values, 5, 1),
            ),
        ];

        for (name, identity_index, family, constraint, values) in invalid_cases
        {
            assert_identity_fails(
                name,
                identity_index,
                family,
                constraint,
                values,
            );
        }
    }
}
