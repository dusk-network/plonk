extern crate criterion;
extern crate merlin;
extern crate plonk;

use bincode;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use merlin::Transcript;
use plonk::commitment_scheme::kzg10::PublicParameters;
use plonk::constraint_system::standard::{proof::Proof, Composer, StandardComposer};
use plonk::fft::EvaluationDomain;

mod serde_benches {
    use super::*;

    pub fn proof_serde(c: &mut Criterion) {
        let public_parameters = PublicParameters::setup(1 << 18, &mut rand::thread_rng()).unwrap();
        let mut composer: StandardComposer = StandardComposer::new();
        // Fill the composer with dummy constraints until it has a
        // size near to DuskNetworks' circuit (2^16 constraints).
        //
        // `add_dummy_constraints` adds 7 constraints to the circuit/call
        // so we need 2^16 / 7 calls to the method ~ 9361
        for _ in 0..9361 {
            composer.add_dummy_constraints();
        }

        let (ck, _) = public_parameters
            .trim(2 * composer.circuit_size().next_power_of_two())
            .unwrap();
        let domain = EvaluationDomain::new(composer.circuit_size()).unwrap();
        let mut transcript = Transcript::new(b"12381");

        // Preprocess circuit
        let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);

        let proof = composer.prove(&ck, &preprocessed_circuit, &mut transcript);
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
