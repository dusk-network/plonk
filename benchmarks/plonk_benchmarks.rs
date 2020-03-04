#![allow(non_snake_case)]

#[macro_use]
extern crate criterion;
extern crate plonk;

use bls12_381::{G1Projective, Scalar};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use plonk::commitment_scheme::kzg10::SRS;
use rand::thread_rng;

mod poly_commit_benches {

    use super::*;
    pub fn bench_polynomial_commitment(c: &mut Criterion) {
        // Generate the powers with size = 1_000_000
        let srs = SRS::setup(1_000_000, &mut thread_rng());
        let (ck, vk) = srs.trim(1_000_000usize);
        let random_poly = (0..1000000)
            .iter()
            .map(|| Scalar::rand(&mut thread_rng()))
            .collect();
        let mut group = c.benchmark_group("Poly commit");
    }
}
