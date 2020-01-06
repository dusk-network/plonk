#[macro_use]
extern crate criterion;
extern crate plonk;
use plonk::cs::composer::StandardComposer;
use plonk::cs::*;

extern crate algebra;
extern crate poly_commit;
use algebra::curves::bls12_381::Bls12_381 as E;
use algebra::fields::bls12_381::Fr;
use algebra::fields::*;
use algebra::UniformRand;
use merlin::Transcript;
use plonk::srs;
use poly_commit::kzg10::UniversalParams;

use criterion::Criterion;


fn prove(n: usize, pp : &UniversalParams<E>) -> proof::Proof<E> {
    let mut composer: StandardComposer<E> = add_dummy_composer(n);

    // setup srs
    let (ck, _) = srs::trim(pp, n + 5).unwrap();

    // setup transcript
    let mut transcript = Transcript::new(b"");


composer.prove(&ck, &mut transcript,&mut rand::thread_rng())

}

// Ensures a + b - c = 0
fn simple_add_gadget(composer: &mut StandardComposer<E>, a: Variable, b: Variable, c: Variable) {
    let q_l = Fr::one();
    let q_r = Fr::one();
    let q_o = -Fr::one();
    let q_c = Fr::zero();

    composer.add_gate(a, b, c, q_l, q_r, q_o, q_c);
}

// Returns a composer with `n` constraints
pub fn add_dummy_composer(n: usize) -> StandardComposer<E> {
    let mut composer = StandardComposer::new();

    let one = Fr::one();
    let two = Fr::one() + &Fr::one();

    let var_one = composer.add_input(one);
    let var_two = composer.add_input(two);

    for _ in 0..n-1 {
        simple_add_gadget(&mut composer, var_one, var_one, var_two);
    }

    let var_five = composer.add_input(Fr::from(5 as u8));
    let var_ten = composer.add_input(Fr::from(10 as u8));

    composer.mul_gate(var_five, var_two, var_ten, Fr::from(2 as u8), Fr::from(8 as u8), Fr::from(10 as u8));

    assert!(n == composer.size());

    composer
}

fn bench_proof_creation(c: &mut Criterion) {

    let mut group = c.benchmark_group("Proof creation");
    
    use std::time::Duration;
    group.measurement_time(Duration::from_secs(120));

    let n = 2usize.pow(21);
    let public_parameters: UniversalParams<E> = srs::setup(n);

    group.bench_function("2_13", |b| b.iter(|| prove(2usize.pow(13), &public_parameters) ));
    group.bench_function("2_14", |b| b.iter(|| prove(2usize.pow(14), &public_parameters) ));
    group.bench_function("2_15", |b| b.iter(|| prove(2usize.pow(15), &public_parameters) ));
    group.bench_function("2_16", |b| b.iter(|| prove(2usize.pow(16), &public_parameters) ));
    group.bench_function("2_17", |b| b.iter(|| prove(2usize.pow(17), &public_parameters) ));
    group.bench_function("2_18", |b| b.iter(|| prove(2usize.pow(18), &public_parameters) ));
    group.bench_function("2_19", |b| b.iter(|| prove(2usize.pow(19), &public_parameters) ));
    group.bench_function("2_20", |b| b.iter(|| prove(2usize.pow(20), &public_parameters) ));

    group.finish();
}


criterion_group!(    name = plonk_prover;
    config = Criterion::default().sample_size(10);
    targets =
    bench_proof_creation,);
criterion_main!(plonk_prover);