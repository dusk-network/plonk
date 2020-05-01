extern crate criterion;
extern crate dusk_plonk;
extern crate merlin;

use bincode;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
use dusk_plonk::proof_system::Proof;
use dusk_plonk::proof_system::Prover;

mod serde_benches {
    use super::*;

    pub fn proof_serde(c: &mut Criterion) {
        let public_parameters = PublicParameters::setup(1 << 18, &mut rand::thread_rng()).unwrap();
        let mut prover = Prover::default();
        // Fill the composer with dummy constraints until it has a
        // size near to DuskNetworks' circuit (2^16 constraints).
        //
        // `add_dummy_constraints` adds 7 constraints to the circuit/call
        // so we need 2^16 / 7 calls to the method ~ 9361
        for _ in 0..9361 {
            prover.mut_cs().add_dummy_constraints();
        }

        let (ck, _) = public_parameters
            .trim(2 * prover.circuit_size().next_power_of_two())
            .unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        let proof = prover.prove(&ck).unwrap();
        let proof_ser_data = bincode::serialize(&proof).unwrap();

        c.bench_with_input(
            BenchmarkId::new("Proof Serde", "Deserialization"),
            &proof_ser_data,
            |b, proof_ser_data| {
                b.iter(|| bincode::deserialize::<Proof>(&proof_ser_data.clone()));
            },
        );

        c.bench_with_input(
            BenchmarkId::new("Proof Serde", "Serialization"),
            &proof,
            |b, proof| {
                b.iter(|| bincode::serialize(&proof.clone()));
            },
        );
    }
}
criterion_group!(benchmarks, serde_benches::proof_serde,);
criterion_main!(benchmarks,);
