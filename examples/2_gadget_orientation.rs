//! So in the previous examples we've seen how we can go through the whole
//! process of creating a circuit, then a proof, and then verify it.
//!
//! Now, we will show which is the most optimal way (from our perspective)
//! to work with plonk and circuits that we want to re-use.
//!
//! On the previous example, we needed a bunch of code just to create a simple
//! `Proof` that wasn't even verified by a different `Composer` (the verifier
//! one).
//!
//! On this example, we will work with the previous circuit using the constraint
//! to `One` as Public Inputs instead of a circuit descriptor.

extern crate bincode;
extern crate merlin;
extern crate plonk;

use dusk-bls12_381::Scalar;
use merlin::Transcript;
use plonk::commitment_scheme::kzg10::{PublicParameters, VerifierKey};
use plonk::constraint_system::StandardComposer;
use plonk::fft::EvaluationDomain;
use plonk::proof_system::{PreProcessedCircuit, Proof};
use std::fs;

/// This function will populate our `Composer` adding to it the witness values that we
/// provide building the example circuit with them.
///
/// This fucntion is intended to be the gadget builder and it can be called by both prover
/// and Verifier to populate a composer and be able to generate a `PreProcessedCircuit`
/// so then they can prove or verify.
fn gadget_builder(composer: &mut StandardComposer, inputs: &[Scalar], final_result: Scalar) {
    // Get my secret inputs as Variables so we are able to use them inside the circuit.
    let a = composer.add_input(inputs[0]);
    let b = composer.add_input(inputs[1]);
    let c = composer.add_input(inputs[2]);
    let d = composer.add_input(inputs[3]);

    // We first need to compute `A + B`. We have two choices here:
    // - Compute the result and set it as output wire.
    // - Get the result from the gate computation itself as a `Variable`
    // representing the output wire of the gate.
    // Since we can get it for free and the constraint will be added independently
    // of providing the result or not, we will go with the second option.

    // As the `add` function states, we are indeed adding the following constraint:
    // `Forces q_l * w_l + q_r * w_r + q_c + PI = w_o(computed by the gate).`
    let a_plus_b = composer.add(
        // q_l , w_l
        (Scalar::one(), a),
        // q_r, w_r
        (Scalar::one(), b),
        // q_c. If we would like to add Constants as part of the circuit description
        // (they're not going to change), we can add them here on q_c.
        Scalar::zero(),
        // Public Inputs
        Scalar::zero(),
    );

    // We do the same for `C + D`. This time we will use a width 4 gate just to show how we
    // should do it. It's obviously not needed since we only have 2 inputs and 1 output. So
    // with width-3 is enough as we saw in the previous gate.
    let c_plus_d = composer.big_add(
        // q_l, w_l
        (Scalar::one(), c),
        // q_r, w_r
        (Scalar::one(), d),
        // q_4, w_4 (Not needed, so we set them to zero).
        // It's important to see that when we need a `zero` variable,
        // we use the one that the `composer` provides instead of generating
        // zero variables everywhere.
        (Scalar::zero(), composer.zero_var),
        // q_c. If we would like to add Constants as part of the circuit description
        // (they're not going to change), we can add them here on q_c.
        Scalar::zero(),
        // Public Inputs
        Scalar::zero(),
    );

    // Now, time to XOR both results!!
    //
    // We need to be smart here. XOR requires `scalar-bits/2 + 1` gates to be performed within
    // a PLONK circuit.
    //
    // So if we know for example that `A + B & C + D` will never need more than 8 bits for example,
    // we can generate a XOR gate that just does the XOR for 10 bits of both numbers.
    //
    // On this way, we basically save a lot of gates since a regular `Scalar` has 254 bits which means
    // 128 gates.
    //
    // Anyway, if you're not sure of what you're doing, we recommend to use 254 bits to be sure that
    // you're not missing anything.
    let ab_xor_cd = composer.logic_xor_gate(a_plus_b, c_plus_d, 14usize);

    // Now that we've XOR'ed our values, it's time to check if the result is
    // really what we expect it to be, a boolean value.
    //
    // To check that fact, we can simply call PLONKs' `bool_gate` which will add
    // a constraint in the circuit that checks if the inputed
    // variable is indeed in the range [0,1].
    composer.bool_gate(ab_xor_cd);

    // Finally we just need to check if the XOR is not only a boolean value, but also and
    // specifically is equal to FINAL_RESULT.
    //
    // Using this way, we need to know that it is applying the following constraint:
    // `ab_xor_cd - q_c + PI = 0`. So we need to give the negative sign to the public inputs
    // to then force the gate to do `ab_xor_cd - q_c + (-PI) = 0
    composer.constrain_to_constant(ab_xor_cd, Scalar::zero(), -final_result);

    // Since we have polynomials inside of our Composer that don't have any coeff != 0 such as q_range,
    // we need to add dummy_constraints which allow us to avoid the `PolynomialDegreeZero` error.
    // It's a sanity check for the end-user to call this function at the end of the implementation of
    // his/her circuit.
    composer.add_dummy_constraints();
}

fn build_proof(
    prover_composer: &mut StandardComposer,
    prover_transcript: &mut Transcript,
) -> Proof {
    // ** Note that we could easily move the following lines to obtain the `PreProcessedCircuit` &
    // `PublicParameters(ck, vk)` inside of a `lazy_static!` implementation which will
    // make everything much more easy.**
    //
    // Anyway we will do it here to represent it.
    //
    // This will give us the order of the circuit that we've built (The number of cates/constraints that our circuit has).
    // Note that since we should have our `PreProcessedCircuit` already stored, we will not need to compute this (the size)
    // is already known.
    let circ_size = prover_composer.circuit_size();
    // The `EvaluationDomain` is built according to the `circuit_size` of our Composer. To generate it we simply do:
    let eval_domain = EvaluationDomain::new(circ_size).unwrap();
    // The Commitment Key `ProverKey` which will allow us to compute the commitments and basically "hide" our secret values.
    // It is derived from the Trusted Setup `PublicParameters`.
    //
    // What we will do now is basically get the previously generated `PublicParameters` (the testing ones) and derive from them
    // the `ProverKey`.
    //
    // Read serialized pub_params from the file where we stored them on the previous example.
    let ser_pub_params = fs::read(&"examples/.public_params.bin")
        .expect("File not found. Run example `0_setup_srs` first please");
    let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();
    // Derive the `ProverKey` from the `PublicParameters`.
    let (prover_key, _) = pub_params
        .trim(2 * prover_composer.circuit_size().next_power_of_two())
        .unwrap();
    let prep_circ = prover_composer.preprocess(&prover_key, prover_transcript, &eval_domain);
    // ** Note that we could easily move the previous lines to obtain the `PreProcessedCircuit` &
    // `PublicParameters(ck, vk)` inside of a `lazy_static!` implementation which will
    // make everything much more easy.**

    // Now we build the proof with the parameters we generated.
    prover_composer.prove(&prover_key, &prep_circ, prover_transcript)
}

// This function could be replaced by a using lazy_static or simply deserializing the values
// that we are returning and generating but could be serialized.
fn gen_verifier_params(
    verif_composer: &mut StandardComposer,
    verif_transcript: &mut Transcript,
) -> (PreProcessedCircuit, VerifierKey) {
    // This will give us the order of the circuit that we've built (The number of cates/constraints that our circuit has).
    // Note that since we should have our `PreProcessedCircuit` already stored, we will not need to compute this (the size)
    // is already known.
    let circ_size = verif_composer.circuit_size();
    // The `EvaluationDomain` is built according to the `circuit_size` of our Composer. To generate it we simply do:
    let eval_domain = EvaluationDomain::new(circ_size).unwrap();
    // The Commitment Key `ProverKey` which will allow us to compute the commitments and basically "hide" our secret values.
    // It is derived from the Trusted Setup `PublicParameters`.
    //
    // What we will do now is basically get the previously generated `PublicParameters` (the testing ones) and derive from them
    // the `ProverKey`.
    //
    // Read serialized pub_params from the file where we stored them on the previous example.
    let ser_pub_params = fs::read(&"examples/.public_params.bin")
        .expect("File not found. Run example `0_setup_srs.rs` first please");
    let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();
    // Derive the `ProverKey` from the `PublicParameters`.
    let (prover_key, verif_key) = pub_params
        .trim(verif_composer.circuit_size().next_power_of_two())
        .unwrap();
    let prep_circ = verif_composer.preprocess(&prover_key, verif_transcript, &eval_domain);
    (prep_circ, verif_key)
}

fn verify_proof(
    proof: &Proof,
    verif_prep_circ: &PreProcessedCircuit,
    verif_key: &VerifierKey,
    verif_transcript: &mut Transcript,
    pub_input: &Scalar,
) -> bool {
    let zero = Scalar::zero();

    proof.verify(
        verif_prep_circ,
        verif_transcript,
        verif_key,
        &[
            zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, *pub_input,
        ],
    )
}

/// The goal of the main function will simulate the place on your code where you
/// consistently create proofs and/or verify them.
fn main() -> () {
    //
    //
    // Prover Point of View
    //
    //
    let mut prover_composer = StandardComposer::new();
    // Generate a Transcript
    let mut prover_transcript = Transcript::new(b"Gadget-Orientation-Is-Cool");
    // Generate one `PreProcessedCircuit` of the circuit we'll be working with and store it
    // so we can always import it from serialized data or whatever on an init function.
    gadget_builder(
        // Our composer
        &mut prover_composer,
        // Inputs that the gadget requires to build the circuit with our witness values
        &[
            Scalar::from(4u64),
            Scalar::from(6u64),
            Scalar::from(3u64),
            Scalar::from(8u64),
        ],
        // Public inputs required at some point of the circuit construction.
        Scalar::one(),
    );

    // Generate a `Proof` with the values we used
    let proof_1 = build_proof(&mut prover_composer, &mut prover_transcript);
    //
    // **We can now build a second proof so easily if we move the code avobe into a function
    // and so, we just have a functions that makes the call with the inputs.**

    //
    //
    // Verifier Point of View
    //
    //

    let mut verifier_composer = StandardComposer::new();
    // Generate a Transcript
    let mut verifier_transcript = Transcript::new(b"Gadget-Orientation-Is-Cool");
    // The verifier needs to have the same `PreProcessedCircuit` (the same vision of)
    // the circuit that the `Prover` has. So normally, we will just build a `PreprocessedCircuit`
    // with whatever values in it (VERIFY HAS NOTHING TO DO WITH THE INPUTS THAT THE VERIFIER ADDS
    // TO THE COMPOSER THAT HE/SHE GENERATES).
    //
    // As mentioned avobe, we could just get our `PreProcessedCircuit` by deserializing it from a file.
    // Anyway, we will do it explicitly here.
    gadget_builder(
        // Our composer
        &mut verifier_composer,
        // From the verifier perspective, these inputs do not matter at all.
        &[
            Scalar::from(999u64),
            Scalar::from(999u64),
            Scalar::from(999u64),
            Scalar::from(999u64),
        ],
        // Public inputs required at some point of the circuit construction.
        Scalar::one(),
    );

    // The following part could be as simple as deserialize data or have a lazy_static reference.
    // We will just call a function that will give us the parametes that we could easily serialize/deserialize.
    let (prep_circ, verif_key) =
        gen_verifier_params(&mut verifier_composer, &mut verifier_transcript);

    assert!(verify_proof(
        &proof_1,
        &prep_circ,
        &verif_key,
        &mut verifier_transcript,
        &-Scalar::one()
    ));
    println!("The proof was succesfully verified!");
}
