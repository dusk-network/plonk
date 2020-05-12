//! In order to construct a `Proof`, we first need to build the circuit
//! over which it operates and it's defined.
//!
//! Building a circuit is something we can achieve by using PLONK's
//! `StandardComposer`. The `StandardComposer` is a struct which has implemented
//! functions to allow the end-user represent the logic of the circuit by compounding
//! the operations that need to be performed with the witnesses and the Public
//! Inputs.
//!
//! The second step to be able to generate the `Proof` is to build a
//! `PreProcessedCircuit` structure, which is a pure definition of the
//! logic of the circuit we will have already built with the help of the
//! `StandardComposer`
//!
//! This is achieved by ordering to our `StandardComposer` to preprocess
//! the logic that we've implemented, which is then returned to us a
//! `PreProcessedCircuit` struct which holds the info of the wire-selector
//! polynomials (the info of the polynomials that describe the operations that
//! we perform in our circuit).
//!
//! We will show in this file how we can construct circuits using PLONKs'
//! `StandardComposer` and then, how to obtain a `PreProcessedCircuit`
//! struct which holds the description of the circuit we've designed
//! to then be able to generate a `Proof` with it.
//!
//! In this example we will create a simple circuit:
//! - We know 4 values A, B, C, D.
//! - we will prove that this 4 numbers satisfy that `A + B ^ C + D == 1`.
//! - We have a public input which is 1.
//! - The circuit will perform: `((A + B ^ C + D) is bool) and also == 1`
//!
//! `Composers` work with `Variables` instead of the `Scalar` values directly
//! when we want to use that `Scalar`s as witness values (secret).
//! `Variables` are some sort of references linked to the original `Scalar` value
//! inside of the `StandardComposer`'s memory.
//! So every time we want to use a new secret value, we need to obtain a `Variable`
//! from it's original value, so it is then marked as "secret".
//!
//! For the rest of the circuit describers, such as the selector polynomials (which
//! define the operations that we do and how we "scale" hidden values), we simply use
//! "Scalar"s since they're not secret nor hidden to anyone.
//! Remember that both `Prover` and `Verifier` have the same view of the circuit description
//! but not for the witness values.

extern crate bincode;
extern crate dusk_plonk;
extern crate merlin;

use dusk_plonk::prelude::*;
use failure::Error;
use std::fs;

fn main() -> Result<(), Error> {
    //
    //
    // Circuit construction stage
    //
    //
    //
    // First of all, let's create our new composer. If we know the size that it will
    // have, calling `with expected size` can decrease the re-allocs and thus improve
    // the performance.
    let mut prover = Prover::new(b"End-To-End-Example");

    let composer = prover.mut_cs();

    // Then we generate our `Scalar` values A, B, C, D that we want to prove,
    // which satisfy the aformentioned properties.
    let a_scalar = Scalar::from(4u64);
    let b_scalar = Scalar::from(6u64);
    let c_scalar = Scalar::from(3u64);
    let d_scalar = Scalar::from(8u64);

    // We also declare the final result we expect as a Scalar.
    let one = Scalar::one();

    // Get my secret inputs as Variables so we are able to use them inside the circuit.
    let a = composer.add_input(a_scalar);
    let b = composer.add_input(b_scalar);
    let c = composer.add_input(c_scalar);
    let d = composer.add_input(d_scalar);

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

    // We do the same for `C + D`. This time we will use a width-4 gate, just to show how it
    // should be done. It's obviously not needed since we only have 2 inputs and 1 output. So
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
    // So if we know, for example, that `A + B & C + D` will never need more than 8 bits,
    // we can generate a XOR gate that just does the XOR for 10 bits of both numbers.
    //
    // By doing this, we basically save a lot of gates since a regular `Scalar` has 254 bits which means
    // 128 gates.
    //
    // Anyway, if you're not sure of what you're doing, we recommend to use 254 bits to be sure that
    // you're not missing anything.
    let ab_xor_cd = composer.logic_xor_gate(a_plus_b, c_plus_d, 10usize);

    // Now that we've XOR'ed our values, it's time to check if the result is
    // really what we expect it to be, a boolean value.
    //
    // To check that fact, we can simply call PLONKs' `bool_gate` which will add
    // a constraint in the circuit that checks if the inputed
    // variable is indeed in the range [0,1].
    composer.bool_gate(ab_xor_cd);

    // Finally we just need to check if the XOR is not only a boolean value, but also check that it is
    // specifically equal to One.
    //
    // If One is something that will not change between proofs, but is publicly known, we will
    // probably want to set One as a circuit descriptor to apply the equalty constraint.
    // If that's the case, then we have different ways to do that.
    //
    // We can use the `constraint_to_constant` gate which will add a constraint that states that
    // a `Variable` is equal in value to a given `Scalar` which will be added to the circuit description.
    composer.constrain_to_constant(ab_xor_cd, one, Scalar::zero());
    // Another way will be to use an `add` gate to perform the subtraction between our variable
    // and One to ensure that the result is 0.
    composer.add_gate(
        // `w_l` (The input that we want to check if is One)
        ab_xor_cd,
        // `w_r` set to zero since we only have one variable value
        composer.zero_var,
        // `w_o` set to zero since it's the output of `Variable(ab_xor_cd) - One` which we want to be
        // equal to zero to apply the constraint.
        composer.zero_var,
        // `q_l` -> Scaling value for `w_l`
        Scalar::one(),
        // `q_r` -> Scaling value for `w_r` (Set to zero since we don't use it).
        Scalar::zero(),
        // `q_o` -> Scaling value for `w_o` (Set to zero since we want it to be zero (even the variable already is))
        Scalar::zero(),
        // `q_c` -> Stores our One subtracting to the variable in order to do `ab_xor_cd - One`
        -one,
        // Public Inputs -> We don't use any public inputs.
        Scalar::zero(),
    );

    // It can happen, that we will not always want to constrain the number to be One, and instead,
    // this One is able to be changed by any other value keeping the same exact circuit.
    //
    // If that's the case, we cannot use One as a circuit descriptor since we would then need to create
    // a entirely new circuit for each different value that we want to use.
    // So what's the solution?
    //
    // We use that value as a Public Input, which means that it's not defining the circuit but at the same
    // time is a publicly known value.
    //
    // We can do it in one of several ways:
    //
    // We can use the `constraint_to_constant` gate which will add a constraint that states that
    // a `Variable` is equal in value to a given `Scalar`. But instead to set the `Scalar` as a circuit
    // descriptor `q_c` we will set it as a Public Input.
    // By doing this, the circuit is not bound to any specific Constant value and we can re-use it with different
    // publicly known values.
    //
    // To apply this method, we need to know that following constraint is being applied:
    // `ab_xor_cd - q_c + PI = 0`. So we need to give the negative sign to the public inputs
    // to then force the gate to peform `ab_xor_cd - q_c + (-PI) = 0`.
    composer.constrain_to_constant(ab_xor_cd, Scalar::zero(), -one);

    // We can also use the same approach as before and go for an addition gate that subtracts the variable
    // to the Public Inputs.
    // To do so, we also need to aply the negative sign to the PI `Scalar` since the constraint eq is:
    // `q_l * w_l + q_r * w_r + q_c + q_o * w_o + PI) = 0`
    composer.add_gate(
        // `w_l` The input that we want to check if is One
        ab_xor_cd,
        // `w_r` set to zero since we only have one variable value
        composer.zero_var,
        // `w_o` set to zero since it's the output of `Variable(ab_xor_cd) - One`, which we want to be
        // equal to zero to apply the constraint.
        composer.zero_var,
        // `q_l` -> Scaling value for `w_l`
        Scalar::one(),
        // `q_r` -> Scaling value for `w_r` (Set to zero since we don't use it).
        Scalar::zero(),
        // `q_o` -> Scaling value for `w_o` (Set to zero since we want it to be zero (even the variable already is))
        Scalar::zero(),
        // `q_c` -> Circuit descriptor constant, we set it to Zero since we don't want to have a circuit that is bound
        // to a specific constant value.
        Scalar::zero(),
        // Public Inputs -> Since we want to be able to change the values to which we constrain our inputs to, without
        // them being circuit descriptors, we add them as Public Inputs and with a negative sign to perform the
        // subtraction.
        -one,
    );

    // Since we have polynomials inside of our Composer that don't have any coeff != 0 such as q_range,
    // we need to add dummy_constraints which allow us to avoid the `PolynomialDegreeZero` error.
    composer.add_dummy_constraints();

    //
    //
    // PreProcessing Stage
    //
    //
    // We've now finished building our circuit. So what we do now?
    // We need to preprocess.
    //
    // Preprocessing the circuit is a step required by the protocol which gives to us a `PreProcessedCircuit`.
    // It is a data structure that holds the commitments to the selector and sigma polynomials.
    //
    // By doing this, we can see the `PreProcessedCircuit` as a "circuit-shape descriptor"
    // since it only stores the commitments that describe the operations that we will perform
    // inside the circuit.
    //
    // Once we have this `PreProcessedCircuit` we can build as many proofs as we want of the same type but with
    // different values having stored all of the circuit logic "compiled" in some way.
    //
    // This will save us time since it's no longer needed to compile again all of the circuit logic every time we
    // want to create a new `Proof` of the same type. We can simply set new values for the input variables and then
    // it's done.
    //
    // 1. The Commitment Key `ProverKey` which will allow us to compute the commitments and basically "hide" our secret values.
    // It is derived from the Trusted Setup `PublicParameters`.
    //
    // What we will do now is basically get the previously generated `PublicParameters` (the testing ones) and derive from them
    // the `ProverKey`.
    //
    // Read serialized pub_params from the file where we stored them on the previous example.
    let ser_pub_params = fs::read(&"examples/.public_params.bin")
        .expect("File not found.\n Run example `0_setup_srs` first please");
    let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();
    // Derive the `ProverKey` from the `PublicParameters`.
    let (prover_key, verifier_key) =
        pub_params.trim(composer.circuit_size().next_power_of_two())?;

    // Now we can finally preprocess the circuit that we've built.
    prover.preprocess(&prover_key)?;

    // We could now store our `PreProcessedCircuit` serialized with `bincode`.
    // let ser_prep_cir = bincode::serialize(&prover.preprocessed_circuit.unwrap()).unwrap();
    // We can store the `PreProcessedCircuit` serialized in a file for later use.
    //
    //fs::write("preprocessed_circ.bin", &ser_prep_cir).expect("Unable to write file");

    // We can do a quick prove and verify process now, since we have our witnesses loaded in the
    // Composer and we also have our circuit preprocessed.

    // With the preprocessed_circuit we can now elaborate proofs with the `witness` values (Variables)
    // that we've loaded into our `Composer`.
    //
    // We clone the transcript since we don't want to modify it to allow then the verifier to re-use it.
    let verifier_transcript = prover.preprocessed_transcript.clone();

    let proof = prover.prove(&prover_key)?;

    let zero = Scalar::zero();
    let one = Scalar::one();

    let mut verifier = Verifier::new(b"End-To-End-Example");
    verifier.preprocessed_transcript = verifier_transcript;
    verifier.preprocessed_circuit = prover.preprocessed_circuit;

    let public_inputs = &vec![
        zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, -one, -one,
    ];

    assert!(verifier
        .verify(&proof, &verifier_key, public_inputs)
        .is_ok());
    println!("Proof verified succesfully!");
    Ok(())
}
