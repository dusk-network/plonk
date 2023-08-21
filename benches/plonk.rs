// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::many_single_char_names)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_plonk::prelude::*;

#[derive(Debug, Clone, Copy)]
struct BenchCircuit<const DEGREE: usize> {
    a: BlsScalar,
    b: BlsScalar,
    x: BlsScalar,
    y: JubJubScalar,
    z: JubJubExtended,
}

impl<const DEGREE: usize> Default for BenchCircuit<DEGREE> {
    fn default() -> Self {
        Self {
            a: BlsScalar::from(2u64),
            b: BlsScalar::from(3u64),
            x: BlsScalar::from(6u64),
            y: JubJubScalar::from(7u64),
            z: dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(7u64),
        }
    }
}

impl<const DEGREE: usize> Circuit for BenchCircuit<DEGREE> {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        let w_a = composer.append_witness(self.a);
        let w_b = composer.append_witness(self.b);
        let w_x = composer.append_witness(self.x);
        let w_y = composer.append_witness(self.y);
        let w_z = composer.append_point(self.z);

        let mut diff = 0;
        let mut prev = composer.constraints();

        while prev + diff < DEGREE {
            let r_w =
                composer.gate_mul(Constraint::new().mult(1).a(w_a).b(w_b));

            composer.append_constant(15);
            composer.append_constant_point(self.z);

            composer.assert_equal(w_x, r_w);
            composer.assert_equal_point(w_z, w_z);

            composer.gate_add(Constraint::new().left(1).right(1).a(w_a).b(w_b));

            composer.component_add_point(w_z, w_z);
            composer.append_logic_and::<128>(w_a, w_b);
            composer.append_logic_xor::<128>(w_a, w_b);
            composer.component_boolean(C::ONE);
            composer.component_decomposition::<254>(w_a);
            composer.component_mul_generator(
                w_y,
                dusk_jubjub::GENERATOR_EXTENDED,
            )?;
            composer.component_mul_point(w_y, w_z);
            composer.component_range::<128>(w_a);
            composer.component_select(C::ONE, w_a, w_b);
            composer.component_select_identity(C::ONE, w_z);
            composer.component_select_one(C::ONE, w_a);
            composer.component_select_point(C::ONE, w_z, w_z);
            composer.component_select_zero(C::ONE, w_a);

            diff = composer.constraints() - prev;
            prev = composer.constraints();
        }

        Ok(())
    }
}

fn run<const DEGREE: usize>(
    c: &mut Criterion,
    pp: &PublicParameters,
    label: &'static [u8],
) {
    let (prover, verifier) =
        Compiler::compile::<BenchCircuit<DEGREE>>(&pp, label)
            .expect("failed to compile circuit");

    let circuit: BenchCircuit<DEGREE> = BenchCircuit::default();

    // sanity run
    let (proof, public_inputs) = prover
        .prove(&mut rand_core::OsRng, &circuit)
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    let power = (DEGREE as f64).log2() as usize;
    let description = format!("Prove 2^{} = {} gates", power, DEGREE);

    c.bench_function(description.as_str(), |b| {
        b.iter(|| black_box(prover.prove(&mut rand_core::OsRng, &circuit)))
    });

    let description = format!("Verify 2^{} = {} gates", power, DEGREE);

    c.bench_function(description.as_str(), |b| {
        b.iter(|| verifier.verify(black_box(&proof), black_box(&public_inputs)))
    });
}

fn constraint_system_benchmark(c: &mut Criterion) {
    const MAX_DEGREE: usize = 17;

    let label = b"dusk-network";
    let pp = PublicParameters::setup(1 << MAX_DEGREE, &mut rand_core::OsRng)
        .expect("failed to generate pp");

    run::<{ 1 << 5 }>(c, &pp, label);
    run::<{ 1 << 6 }>(c, &pp, label);
    run::<{ 1 << 7 }>(c, &pp, label);
    run::<{ 1 << 8 }>(c, &pp, label);
    run::<{ 1 << 9 }>(c, &pp, label);
    run::<{ 1 << 10 }>(c, &pp, label);
    run::<{ 1 << 11 }>(c, &pp, label);
    run::<{ 1 << 12 }>(c, &pp, label);
    run::<{ 1 << 13 }>(c, &pp, label);
    run::<{ 1 << 14 }>(c, &pp, label);
    run::<{ 1 << 15 }>(c, &pp, label);
    run::<{ 1 << 16 }>(c, &pp, label);
    run::<{ 1 << 17 }>(c, &pp, label);
}

criterion_group! {
    name = plonk;
    config = Criterion::default().sample_size(10);
    targets = constraint_system_benchmark
}
criterion_main!(plonk);
