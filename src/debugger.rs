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

    fn shifted_wire_value(
        &self,
        constraint_index: usize,
        wire: WiredWitness,
    ) -> BlsScalar {
        self.constraints
            .get(constraint_index + 1)
            .map(|(_, constraint)| self.wire_value(constraint, wire))
            .unwrap_or_default()
    }

    fn evaluates_to_zero(
        &self,
        constraint_index: usize,
        constraint: &Constraint,
    ) -> bool {
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

        let gated_identity_is_zero =
            |selector, identity| selector * identity == BlsScalar::zero();

        let arithmetic =
            (qm * a * b + ql * a + qr * b + qo * c + qf * d + qc) * qarith + pi;
        if arithmetic != BlsScalar::zero() {
            return false;
        }

        let four = BlsScalar::from(4u64);
        let range_identities = [
            range_delta(c - four * d),
            range_delta(b - four * c),
            range_delta(a - four * b),
            range_delta(d_w - four * a),
        ];
        if range_identities
            .into_iter()
            .any(|identity| !gated_identity_is_zero(qrange, identity))
        {
            return false;
        }

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
        if logic_identities
            .into_iter()
            .any(|identity| !gated_identity_is_zero(qlogic, identity))
        {
            return false;
        }

        let bit = extract_bit(&d, &d_w);
        let y_alpha = bit.square() * (qr - BlsScalar::one()) + BlsScalar::one();
        let x_alpha = ql * bit;
        let fixed_base_identities = [
            check_bit_consistency(bit),
            bit * qc - c,
            a_w + a_w * c * a * b * EDWARDS_D - (a * y_alpha + b * x_alpha),
            b_w - b_w * c * a * b * EDWARDS_D - (b * y_alpha + a * x_alpha),
        ];
        if fixed_base_identities
            .into_iter()
            .any(|identity| !gated_identity_is_zero(qfixed_add, identity))
        {
            return false;
        }

        let x1_y2 = d_w;
        let y1_x2 = b * c;
        let variable_base_identities = [
            a * d - x1_y2,
            x1_y2 + y1_x2 - (a_w + a_w * EDWARDS_D * x1_y2 * y1_x2),
            b * d + a * c - (b_w - b_w * EDWARDS_D * x1_y2 * y1_x2),
        ];
        variable_base_identities
            .into_iter()
            .all(|identity| gated_identity_is_zero(qgroup_variable, identity))
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
                self.write_output();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn evaluates_all_gate_identities() {
        let zeroes = [BlsScalar::zero(); 8];
        let valid_constraints = [
            Constraint::arithmetic(&Constraint::new()),
            Constraint::range(&Constraint::new()),
            Constraint::logic(&Constraint::new()),
            Constraint::logic_xor(&Constraint::new()),
            Constraint::group_add_fixed_base(&Constraint::new()),
            Constraint::group_add_variable_base(&Constraint::new()),
        ];

        for constraint in valid_constraints {
            let debugger = wire_rows(constraint, zeroes);
            assert!(debugger.evaluates_to_zero(0, &debugger.constraints[0].1));
        }

        let invalid_cases = [
            (
                Constraint::arithmetic(&Constraint::new().constant(1u64)),
                zeroes,
            ),
            (
                Constraint::range(&Constraint::new()),
                [
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::from(4u64),
                ],
            ),
            (
                Constraint::logic(&Constraint::new()),
                [
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                ],
            ),
            (
                Constraint::group_add_fixed_base(&Constraint::new()),
                [
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                ],
            ),
            (
                Constraint::group_add_variable_base(&Constraint::new()),
                [
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    BlsScalar::one(),
                ],
            ),
            (Constraint::range(&Constraint::new().public(1u64)), zeroes),
        ];

        for (case, (constraint, values)) in
            invalid_cases.into_iter().enumerate()
        {
            let debugger = wire_rows(constraint, values);
            assert!(
                !debugger.evaluates_to_zero(0, &debugger.constraints[0].1),
                "invalid gate case {case} evaluated as satisfied"
            );
        }
    }
}
