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

use crate::constraint_system::{Constraint, Selector, WiredWitness, Witness};
use crate::runtime::RuntimeEvent;

/// PLONK debugger
#[derive(Debug, Clone)]
pub(crate) struct Debugger {
    witnesses: Vec<(EncodableSource, Witness, BlsScalar)>,
    constraints: Vec<(EncodableSource, Constraint)>,
}

impl Debugger {
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

        let constraints =
            self.constraints
                .iter()
                .enumerate()
                .map(|(id, (source, c))| {
                    let source = source.clone();

                    let qm = c.coeff(Selector::Multiplication);
                    let ql = c.coeff(Selector::Left);
                    let qr = c.coeff(Selector::Right);
                    let qd = c.coeff(Selector::Fourth);
                    let qc = c.coeff(Selector::Constant);
                    let qo = c.coeff(Selector::Output);
                    let pi = c.coeff(Selector::PublicInput);
                    let qarith = c.coeff(Selector::Arithmetic);
                    let qlogic = c.coeff(Selector::Logic);
                    let qrange = c.coeff(Selector::Range);
                    let qgroup_variable =
                        c.coeff(Selector::GroupAddVariableBase);
                    let qfixed_add = c.coeff(Selector::GroupAddFixedBase);

                    let witnesses = WiredWitnesses {
                        a: c.witness(WiredWitness::A).index(),
                        b: c.witness(WiredWitness::B).index(),
                        d: c.witness(WiredWitness::D).index(),
                        o: c.witness(WiredWitness::O).index(),
                    };

                    let wa = self
                        .witnesses
                        .get(witnesses.a)
                        .map(|(_, _, v)| *v)
                        .unwrap_or_default();

                    let wb = self
                        .witnesses
                        .get(witnesses.b)
                        .map(|(_, _, v)| *v)
                        .unwrap_or_default();

                    let wd = self
                        .witnesses
                        .get(witnesses.d)
                        .map(|(_, _, v)| *v)
                        .unwrap_or_default();

                    let wo = self
                        .witnesses
                        .get(witnesses.o)
                        .map(|(_, _, v)| *v)
                        .unwrap_or_default();

                    // TODO check arith, range, logic & ecc wires
                    let evaluation = qm * wa * wb
                        + ql * wa
                        + qr * wb
                        + qd * wd
                        + qo * wo
                        + qc
                        + pi;

                    let evaluation = evaluation == BlsScalar::zero();

                    let selectors = Selectors {
                        qm: qm.to_bytes().into(),
                        ql: ql.to_bytes().into(),
                        qr: qr.to_bytes().into(),
                        qd: qd.to_bytes().into(),
                        qc: qc.to_bytes().into(),
                        qo: qo.to_bytes().into(),
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
                });

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

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            witnesses: Vec::with_capacity(capacity),
            constraints: Vec::with_capacity(capacity),
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
