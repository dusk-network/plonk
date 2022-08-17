// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Debugger module

use std::env;
use std::path::PathBuf;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_cdf::{
    BaseConfig, Config, Constraint as CdfConstraint, Encoder, IndexedWitness,
    Polynomial, Source, Witness as CdfWitness,
};

use crate::constraint_system::{Constraint, Selector, WiredWitness, Witness};
use crate::runtime::RuntimeEvent;

/// PLONK debugger
#[derive(Debug, Clone)]
pub(crate) struct Debugger {
    witnesses: Vec<(Source, Witness, BlsScalar)>,
    constraints: Vec<(Source, Constraint)>,
}

impl Debugger {
    /// Resolver the caller function
    fn resolve_caller() -> Source {
        let mut source = None;

        backtrace::trace(|frame| {
            // Resolve this instruction pointer to a symbol name
            backtrace::resolve_frame(frame, |symbol| {
                if symbol
                    .name()
                    .map(|n| format!("{}", n))
                    .filter(|s| !s.starts_with("backtrace::"))
                    .filter(|s| !s.starts_with("dusk_plonk::"))
                    .filter(|s| !s.starts_with("core::"))
                    .filter(|s| !s.starts_with("std::"))
                    .is_some()
                {
                    if let Some(path) = symbol.filename() {
                        let line = symbol.lineno().unwrap_or_default() as u64;
                        let col = symbol.colno().unwrap_or_default() as u64;
                        let path = path.canonicalize().unwrap_or_default();
                        let path = format!("{}", path.display()).into();

                        source.replace(Source::new(line, col, path));
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

            CdfWitness::new(id, value, source)
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
                    let qrange = c.coeff(Selector::Range);
                    let qlogic = c.coeff(Selector::Logic);
                    let qfixed_add = c.coeff(Selector::GroupAddFixedBase);
                    let qvariable_add = c.coeff(Selector::GroupAddVariableBase);

                    let wai = c.witness(WiredWitness::A).index();
                    let wbi = c.witness(WiredWitness::B).index();
                    let wdi = c.witness(WiredWitness::D).index();
                    let woi = c.witness(WiredWitness::O).index();

                    let wav = self
                        .witnesses
                        .get(wai)
                        .map(|(_, _, v)| *v)
                        .unwrap_or_default();

                    let wbv = self
                        .witnesses
                        .get(wbi)
                        .map(|(_, _, v)| *v)
                        .unwrap_or_default();

                    let wdv = self
                        .witnesses
                        .get(wdi)
                        .map(|(_, _, v)| *v)
                        .unwrap_or_default();

                    let wov = self
                        .witnesses
                        .get(woi)
                        .map(|(_, _, v)| *v)
                        .unwrap_or_default();

                    // TODO check arith, range, logic & ecc wires
                    let eval = qm * wav * wbv
                        + ql * wav
                        + qr * wbv
                        + qd * wdv
                        + qo * wov
                        + qc
                        + pi;

                    let re = eval == BlsScalar::zero();

                    let qm = qm.to_bytes().into();
                    let ql = ql.to_bytes().into();
                    let qr = qr.to_bytes().into();
                    let qd = qd.to_bytes().into();
                    let qc = qc.to_bytes().into();
                    let qo = qo.to_bytes().into();
                    let pi = pi.to_bytes().into();
                    let qarith = qarith.to_bytes().into();
                    let qlogic = qlogic.to_bytes().into();
                    let qvariable_add = qvariable_add.to_bytes().into();

                    // TODO add these to CDF
                    let _ = (qrange, qfixed_add);

                    // TODO IndexedWitness is to be deprecated in favor of a
                    // simplified index

                    let wav = wav.to_bytes().into();
                    let wbv = wbv.to_bytes().into();
                    let wdv = wdv.to_bytes().into();
                    let wov = wov.to_bytes().into();

                    let wa = IndexedWitness::new(wai, None, wav);
                    let wb = IndexedWitness::new(wbi, None, wbv);
                    let wd = IndexedWitness::new(wdi, None, wdv);
                    let wo = IndexedWitness::new(woi, None, wov);

                    let poly = Polynomial::new(
                        qm,
                        ql,
                        qr,
                        qd,
                        qc,
                        qo,
                        pi,
                        qarith,
                        qlogic,
                        qvariable_add,
                        wa,
                        wb,
                        wd,
                        wo,
                        re,
                    );

                    CdfConstraint::new(id, poly, source)
                });

        if let Err(e) = Config::load()
            .and_then(|config| {
                Encoder::init_file(config, witnesses, constraints, &path)
            })
            .and_then(|mut c| c.write_all())
        {
            eprintln!(
                "failed to output CDF file to '{}': {}",
                path.display(),
                e
            );
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
