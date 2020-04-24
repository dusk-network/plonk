//! We will here see how to prepare the setup that the final gadget orientation
//! requires to work fast and with clean code solutions.
//!
//! We basically need to serialize a couple of structures that will be always the
//! same such as:
//! - EvaluationDomain
//! - PreProcessedCircuit
//! - PublicParameters (was done on example 0 so it's not going to be done here).
//!
extern crate bincode;
extern crate merlin;
extern crate plonk;

use bls12_381::Scalar;
use merlin::Transcript;
use plonk::commitment_scheme::kzg10::PublicParameters;
use plonk::constraint_system::StandardComposer;
use plonk::fft::EvaluationDomain;
use plonk::proof_system::{PreProcessedCircuit, Proof, Prover, Verifier};
use std::fs;

// To do this, we basically need to import our gadget builder function.
fn gadget_builder(composer: &mut StandardComposer, inputs: &[Scalar], final_result: Scalar) {
    let a = composer.add_input(inputs[0]);
    let b = composer.add_input(inputs[1]);
    let c = composer.add_input(inputs[2]);
    let d = composer.add_input(inputs[3]);

    let a_plus_b = composer.add(
        (Scalar::one(), a),
        (Scalar::one(), b),
        Scalar::zero(),
        Scalar::zero(),
    );

    let c_plus_d = composer.big_add(
        (Scalar::one(), c),
        (Scalar::one(), d),
        (Scalar::zero(), composer.zero_var),
        Scalar::zero(),
        Scalar::zero(),
    );

    let ab_xor_cd = composer.logic_xor_gate(a_plus_b, c_plus_d, 14usize);
    composer.bool_gate(ab_xor_cd);
    composer.constrain_to_constant(ab_xor_cd, Scalar::zero(), final_result);
    composer.add_dummy_constraints();
}

fn build_prep_circ() -> PreProcessedCircuit {
    // Generate a composer & fill it with whatever witnesses (they're not related)
    // to the PreProcessedCircuit structure at all
    let mut composer = StandardComposer::new();
    let mut transcript = Transcript::new(b"Gadget-Orientation-Is-Cool");
    gadget_builder(
        &mut composer,
        &[Scalar::one(), Scalar::one(), Scalar::one(), Scalar::one()],
        Scalar::one(),
    );
    let circ_size = composer.circuit_size();
    let eval_domain = EvaluationDomain::new(circ_size).unwrap();
    let ser_pub_params = fs::read(&"examples/.public_params.bin")
        .expect("File not found. Run example `0_setup_srs` first please");
    let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();
    // Derive the `ProverKey` from the `PublicParameters`.
    let (prover_key, _) = pub_params
        .trim(2 * composer.circuit_size().next_power_of_two())
        .unwrap();
    let prep_circ = composer.preprocess(&prover_key, &mut transcript);
    prep_circ
}

fn build_proof(inputs: &[Scalar], final_result: Scalar, prep_circ: &PreProcessedCircuit) -> Proof {
    let mut prover = Prover::new(b"Gadget-Orientation-Is-Cool");
    gadget_builder(prover.mut_cs(), inputs, final_result);
    let ser_pub_params = fs::read(&"examples/.public_params.bin")
        .expect("File not found. Run example `0_setup_srs` first please");
    let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();
    // Derive the `ProverKey` from the `PublicParameters`.
    let (prover_key, _) = pub_params
        .trim(2 * prover.circuit_size().next_power_of_two())
        .unwrap();
    prover.prove(&prover_key)
}

fn main() {
    // Generate the preprocessed circuit & serialize it.
    let prep_circ = build_prep_circ();

    let ser_prep_circ = bincode::serialize(&prep_circ).unwrap();
    fs::write("examples/.prep_circ_2_3.bin", &ser_prep_circ).expect("Unable to write file");

    // Now we will build a correct and an incorrect proof to use them in the next
    // example. This is not needed, but it will generate a few proofs to be tested
    // later.

    // The public input is PUBLIC so we assume that the `Provers` and `Verifiers`
    // already know it.
    let pub_input = -Scalar::one();

    // Build & serialize OK proof
    let inputs = vec![
        Scalar::from(6u64),
        Scalar::from(4u64),
        Scalar::from(3u64),
        Scalar::from(8u64),
    ];
    let ok_proof = build_proof(&inputs, pub_input, &prep_circ);
    let ser_proof_ok = bincode::serialize(&ok_proof).unwrap();
    fs::write("examples/.proof_ok_2_3.bin", &ser_proof_ok).expect("Unable to write file");

    // Build & serialize KO proof
    let bad_inputs = vec![
        Scalar::from(73u64),
        Scalar::from(449u64),
        Scalar::from(999u64),
        Scalar::from(9329u64),
    ];

    let ko_proof = build_proof(&bad_inputs, pub_input, &prep_circ);
    let ser_proof_ko = bincode::serialize(&ko_proof).unwrap();
    fs::write("examples/.proof_ko_2_3.bin", &ser_proof_ko).expect("Unable to write file");

    println!("Files were written successfully!");
}
