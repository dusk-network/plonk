// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::hint::black_box;

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group,
    criterion_main,
};
use dusk_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use dusk_bytes::Serializable;
use dusk_plonk::prelude::PublicParameters;

const POINTS: usize = (1 << 17) + 1;

fn raw_fixture() -> Vec<u8> {
    // Benchmark-only SRS with public setup secret 2. Doubling generates
    // distinct powers [2^i]G quickly and keeps the fixture deterministic.
    let mut powers = Vec::with_capacity(POINTS);
    let mut point = G1Projective::generator();
    for _ in 0..POINTS {
        powers.push(point);
        point = point.double();
    }
    let mut affine = vec![G1Affine::identity(); POINTS];
    G1Projective::batch_normalize(&powers, &mut affine);

    // The compressed opening key precedes the count and raw G1 powers.
    let h = G2Projective::generator();
    let mut bytes = G1Affine::generator().to_bytes().to_vec();
    bytes.extend_from_slice(&G2Affine::from(h).to_bytes());
    bytes.extend_from_slice(&G2Affine::from(h.double()).to_bytes());
    bytes.extend_from_slice(&(POINTS as u64).to_le_bytes());
    for point in affine {
        bytes.extend_from_slice(&point.to_raw_bytes());
    }
    bytes
}

fn raw_decoding(c: &mut Criterion) {
    let bytes = raw_fixture();
    let pp = PublicParameters::from_raw_var_bytes(&bytes)
        .expect("benchmark fixture must decode");
    assert_eq!(pp.max_degree(), POINTS - 1);
    assert!(pp.to_raw_var_bytes() == bytes, "raw bytes must round trip");
    drop(pp);

    #[cfg(feature = "std")]
    let mode = format!("std_{}_threads", rayon::current_num_threads());
    #[cfg(not(feature = "std"))]
    let mode = "alloc_only";

    let mut group = c.benchmark_group("raw_decoding");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.sampling_mode(SamplingMode::Flat).sample_size(10);
    group.bench_function(BenchmarkId::new("degree_2^17", mode), |b| {
        b.iter(|| {
            PublicParameters::from_raw_var_bytes(black_box(bytes.as_slice()))
                .expect("benchmark fixture must decode")
        });
    });
    group.finish();
}

criterion_group!(benches, raw_decoding);
criterion_main!(benches);
