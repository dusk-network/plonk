// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use dusk_plonk::prelude::*;

#[derive(Default)]
struct VerificationCircuit;

impl Circuit for VerificationCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        for input in 1..=32u64 {
            composer.append_public(input);
        }

        Ok(())
    }
}

fn verification_benchmark(c: &mut Criterion) {
    let pp = PublicParameters::setup(1 << 6, &mut rand_core::OsRng)
        .expect("failed to generate pp");
    let (prover, verifier) =
        Compiler::compile::<VerificationCircuit>(&pp, b"dusk-network")
            .expect("failed to compile circuit");
    let (proof, public_inputs) = prover
        .prove(&mut rand_core::OsRng, &VerificationCircuit)
        .expect("failed to prove");

    assert_eq!(public_inputs.len(), 32);
    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    c.bench_function("Verify 32 public inputs", |b| {
        b.iter(|| verifier.verify(black_box(&proof), black_box(&public_inputs)))
    });
}

criterion_group! {
    name = verification;
    config = Criterion::default().sample_size(10);
    targets = verification_benchmark
}
criterion_main!(verification);
