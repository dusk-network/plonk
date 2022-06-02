// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::many_single_char_names)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_plonk::prelude::*;
use rand_core::OsRng;

#[derive(Debug, Clone, Copy)]
struct BenchCircuit {
    degree: usize,
}

impl<T> From<T> for BenchCircuit
where
    T: Into<usize>,
{
    fn from(degree: T) -> Self {
        Self {
            degree: 1 << degree.into(),
        }
    }
}

impl Circuit for BenchCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), Error> {
        let mut a = BlsScalar::from(2u64);
        let mut b = BlsScalar::from(3u64);
        let mut c;

        while composer.gates() < self.padded_gates() {
            a += BlsScalar::one();
            b += BlsScalar::one();
            c = a * b + a + b + BlsScalar::one();

            let x = composer.append_witness(a);
            let y = composer.append_witness(b);
            let z = composer.append_witness(c);

            let constraint = Constraint::new()
                .mult(1)
                .left(1)
                .right(1)
                .output(-BlsScalar::one())
                .constant(1)
                .a(x)
                .b(y)
                .o(z);

            composer.append_gate(constraint);
        }

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        self.degree
    }
}

fn constraint_system_prove(
    circuit: &mut BenchCircuit,
    pp: &PublicParameters,
    pk: &ProverKey,
    label: &'static [u8],
) -> Proof {
    circuit
        .prove(pp, pk, label, &mut OsRng)
        .expect("Failed to prove bench circuit!")
}

fn constraint_system_benchmark(c: &mut Criterion) {
    let initial_degree = 5;
    let final_degree = 17;

    let rng = &mut rand_core::OsRng;
    let label = b"dusk-network";
    let pp = PublicParameters::setup(1 << final_degree, rng)
        .expect("Failed to create PP");

    let data: Vec<(BenchCircuit, ProverKey, VerifierData, Proof)> =
        (initial_degree..=final_degree)
            .map(|degree| {
                let mut circuit = BenchCircuit::from(degree as usize);
                let (pk, vd) =
                    circuit.compile(&pp).expect("Failed to compile circuit!");

                let proof =
                    constraint_system_prove(&mut circuit, &pp, &pk, label);

                BenchCircuit::verify(&pp, &vd, &proof, &[], label)
                    .expect("Failed to verify bench circuit");

                (circuit, pk, vd, proof)
            })
            .collect();

    data.iter().for_each(|(mut circuit, pk, _, _)| {
        let size = circuit.padded_gates();
        let power = (size as f64).log2() as usize;
        let description = format!("Prove 2^{} = {} gates", power, size);

        c.bench_function(description.as_str(), |b| {
            b.iter(|| {
                constraint_system_prove(black_box(&mut circuit), &pp, pk, label)
            })
        });
    });

    data.iter().for_each(|(circuit, _, vd, proof)| {
        let size = circuit.padded_gates();
        let power = (size as f64).log2() as usize;
        let description = format!("Verify 2^{} = {} gates", power, size);

        c.bench_function(description.as_str(), |b| {
            b.iter(|| {
                BenchCircuit::verify(&pp, vd, black_box(proof), &[], label)
                    .expect("Failed to verify bench circuit!");
            })
        });
    });
}

criterion_group! {
    name = plonk;
    config = Criterion::default().sample_size(10);
    targets = constraint_system_benchmark
}
criterion_main!(plonk);
