//! So in the previous examples we've seen how we can go through the whole
//! process of creating a circuit, then a proof, and then verify it.
//!
//! Now, we will show which is the most optimal way (from our perspective)
//! to work with PLONK and circuits that we want to re-use.
//!
//! On the previous example, we needed a bunch of code just to create a simple
//! `Proof` that wasn't even verified by a different `Composer` (the verifier
//! one).
//!
//! On this example, we will work with the previous circuit using the constraint
//! to `One` as Public Inputs instead of a circuit descriptor.

extern crate bincode;
extern crate dusk_plonk;
extern crate merlin;

use dusk_bls12_381::Scalar;
use dusk_plonk::commitment_scheme::kzg10::{OpeningKey, PublicParameters};
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::proof_system::{Proof, Prover, Verifier};
use failure::Error;
use std::fs;

/// This function will populate our `Composer` adding to it the witness values that we
/// provide building the example circuit with them.
///
/// This function is intended to be the gadget builder and it can be called by both prover
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
    // whether the result is or isn't provided, then we will choose the second
    // option.

    // As the `add` function states, we are indeed adding the following constraint:
    // `Forces q_l * w_l + q_r * w_r + q_c + PI = w_o (computed by the gate).`
    let a_plus_b = composer.add(
        // q_l , w_l
        (Scalar::one(), a),
        // q_r, w_r
        (Scalar::one(), b),
        // q_c. If we would like to add Constants as part of the circuit description
        // (they're not going to change), we can add them on the q_c selector.
        Scalar::zero(),
        // Public Inputs
        Scalar::zero(),
    );

    // We do the same for `C + D`. This time we will use a width-4 gate just to show how we
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
        // (they're not going to change), we can add them on the q_c selector.
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
    // By doing this, we basically save a lot of gates since a regular `Scalar` has 254 bits which means
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

fn build_proof(prover: &mut Prover) -> Result<Proof, Error> {
    // The Commitment Key allows us to commit to polynomials bounded by a degree `d`.
    // The commitment Key is derived from the Trusted Setup `PublicParameters`.
    //
    //
    // The following example shows how to deserialise the public parameters and use them in a proof.
    // These parameters were serialised and stored in in the previous example.
    let ser_pub_params = fs::read(&"examples/.public_params.bin")
        .expect("File not found. Run example `0_setup_srs` first please");
    let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();

    // Derive the `ProverKey` from the `PublicParameters`.
    let (prover_key, _) = pub_params.trim(2 * prover.circuit_size())?;

    // Preprocess the circuit
    prover.preprocess(&prover_key)?;

    // Now we build the proof with the parameters we generated.
    prover.prove(&prover_key)
}

fn generate_verifier_parameters(verifier: &mut Verifier) -> Result<OpeningKey, Error> {
    // The Verifier will deserialise the Public parameters which were serialised and stored
    // from a previous example and pre-process the circuit.
    let ser_pub_params = fs::read(&"examples/.public_params.bin")
        .expect("File not found. Run example `0_setup_srs.rs` first please");
    let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();

    // Derive the Commit and Verifier Key from the `PublicParameters`.
    let (prover_key, verif_key) = pub_params.trim(verifier.circuit_size().next_power_of_two())?;

    // Use the commit key to preprocess the circuit
    verifier.preprocess(&prover_key)?;

    Ok(verif_key)
}

fn verify_proof(
    proof: &Proof,
    verifier: &Verifier,
    verifier_key: &OpeningKey,
    pub_input: &Scalar,
) -> Result<(), Error> {
    let zero = Scalar::zero();

    let public_inputs = &[
        zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, *pub_input,
    ];

    verifier.verify(proof, &verifier_key, public_inputs)
}

/// The goal of the main function is to simulate the place within your code where you
/// consistently create proofs and/or verify them.
fn main() -> Result<(), Error> {
    //
    //
    // Prover's Point of View
    //
    //
    let mut prover = Prover::new(b"Gadget-Orientation-Is-Cool");
    // Generate one `PreProcessedCircuit` of the circuit we'll be working with and store it
    // so we can always import it from serialized data or whatever on an init function.
    gadget_builder(
        // Our composer
        prover.mut_cs(),
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

    // Generate a `Proof` that the gadget is satisfied
    let proof_1 = build_proof(&mut prover)?;
    //
    // One can build another proof using the same circuit, by passing the prover struct through the same gadget with different witness values

    //
    //
    // Verifier Point of View
    //
    //
    let mut verifier = Verifier::new(b"Gadget-Orientation-Is-Cool");

    gadget_builder(
        // Our composer
        verifier.mut_cs(),
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
    // We will just call a function that will give us the parameters that we could easily serialize/deserialize.
    let verifier_key = generate_verifier_parameters(&mut verifier)?;

    verify_proof(&proof_1, &verifier, &verifier_key, &-Scalar::one())?;
    println!("The proof was succesfully verified!");
    Ok(())
}
