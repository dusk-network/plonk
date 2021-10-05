// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_bls12_381::BlsScalar;
use dusk_plonk::circuit::{self, Circuit, VerifierData};
// Using prelude until PP is available on regular import path
use dusk_plonk::constraint_system::TurboComposer;
use dusk_plonk::error::Error;
use dusk_plonk::prelude::PublicParameters;
use dusk_plonk::proof_system::{Proof, ProverKey};

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

        let zero = composer.constant_zero();

        while composer.constraints() < self.padded_constraints() {
            a += BlsScalar::one();
            b += BlsScalar::one();
            c = a * b + a + b + BlsScalar::one();

            let x = composer.append_witness(a);
            let y = composer.append_witness(b);
            let z = composer.append_witness(c);

            composer.append_constraint(
                x,
                y,
                z,
                zero,
                BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::one(),
                -BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::one(),
                None,
            );
        }

        Ok(())
    }

    fn to_public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_constraints(&self) -> usize {
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
        .prove(&pp, &pk, label)
        .expect("Failed to prove bench circuit!")
}

fn constraint_system_benchmark(c: &mut Criterion) {
    let initial_degree = 5;
    let final_degree = 18;

    let rng = &mut rand_core::OsRng;
    let label = b"dusk-network";
    let pp = PublicParameters::setup(1 << (final_degree - 1), rng)
        .expect("Failed to create PP");

    let data: Vec<(BenchCircuit, ProverKey, VerifierData, Proof)> =
        (initial_degree..final_degree)
            .map(|degree| {
                let mut circuit = BenchCircuit::from(degree as usize);
                let (pk, vd) =
                    circuit.compile(&pp).expect("Failed to compile circuit!");

                let proof =
                    constraint_system_prove(&mut circuit, &pp, &pk, label);

                circuit::verify_proof(
                    &pp,
                    vd.key(),
                    &proof,
                    &[],
                    vd.public_inputs_indexes(),
                    label,
                )
                .expect("Failed to verify bench circuit!");

                (circuit, pk, vd, proof)
            })
            .collect();

    data.iter().for_each(|(circuit, pk, _, _)| {
        let mut circuit = circuit.clone();
        let size = circuit.padded_constraints();
        let power = (size as f64).log2() as usize;
        let description = format!("Prove 2^{} = {} constraints", power, size);

        c.bench_function(description.as_str(), |b| {
            b.iter(|| {
                constraint_system_prove(black_box(&mut circuit), &pp, pk, label)
            })
        });
    });

    data.iter().for_each(|(circuit, _, vd, proof)| {
        let size = circuit.padded_constraints();
        let power = (size as f64).log2() as usize;
        let description = format!("Verify 2^{} = {} constraints", power, size);

        c.bench_function(description.as_str(), |b| {
            b.iter(|| {
                circuit::verify_proof(
                    &pp,
                    vd.key(),
                    black_box(proof),
                    &[],
                    vd.public_inputs_indexes(),
                    label,
                )
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
