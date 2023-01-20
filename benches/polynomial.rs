use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use rand_core::OsRng;
use zero_crypto::common::Group;
use zero_plonk::prelude::*;

fn polynomial_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("polynomial");

    for i in 8..=18 {
        let p1 =
            Polynomial::from_coefficients_vec(vec![
                BlsScalar::random(OsRng);
                i
            ]);

        let p2 =
            Polynomial::from_coefficients_vec(vec![
                BlsScalar::random(OsRng);
                i
            ]);

        group.bench_function(BenchmarkId::new("ruffini", i), |b| {
            b.iter(|| {
                black_box(p1.ruffini(black_box(BlsScalar::random(OsRng))))
            })
        });

        group.bench_function(BenchmarkId::new("evaluate", i), |b| {
            b.iter(|| {
                black_box(p1.evaluate(black_box(&BlsScalar::random(OsRng))))
            })
        });

        group.bench_function(BenchmarkId::new("add", i), |b| {
            b.iter(|| black_box(black_box(&p1) + black_box(&p2)))
        });

        group.bench_function(BenchmarkId::new("sub", i), |b| {
            b.iter(|| black_box(black_box(&p1) - black_box(&p2)))
        });
    }
}

criterion_group!(polynomial, polynomial_bench);
criterion_main!(polynomial);
