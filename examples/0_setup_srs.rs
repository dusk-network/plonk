//! PLONK is a ZK-Proving algorithm which requires the usage
//! of a Trusted Setup to be able to work correctly.
//!
//! This plonk crate comes with a commitment scheme module
//! implemented with it so people doesn't need to import it
//! from other sides just to be able to perform tests or even
//! build it's `Proof`s.
//!
//! To be precise, plonk comes with the `KZG10` polynomial
//! commitment scheme implemented on it. Which appart of other
//! functionalities allows us to setup "testing" or "debbuging"
//! Trusted Setups (identified as `PublicParameters` by this repo).
//! With this, end-users are able to perform it's Prove&Verify tests
//! without needing to compute a "real Trusted Setup".
//!
//! **DO NOT USE** `PublicParameters` as you Trusted Setups in production
//! since they require complex Multi-Party computation processes
//! to be setted up in a secure and correct way.
//!
//! ## Why do we care about that?
//!
//! Well, basically to be able to generate `Proof`s, we need to be able to
//! commit our polynomials and for that, we basically need a Trusted Setup
//! and a polynomial commitment scheme that allow us to generate this structures
//! and/or use them alongside with plonk.
//!
//! On this quick example we will see how to generate a Trusted Setup, represented
//! by plonk's `PublicParameters` data structure to then be able to generate
//! `Proof`s and `PreProcessedCircuit`s as well as verify these `Proof`s.

extern crate bincode;
extern crate plonk;
extern crate rand;

use plonk::commitment_scheme::kzg10::PublicParameters;
use std::fs;

fn main() -> () {
    // First of all we generate our `PublicParameters` data structure.
    // NOTE that we need to specify the `size` of them.
    //
    // This `size` is usually set as the next_power_of_two of the CIRCUIT_SIZE
    // that we are expecting to have.
    //
    // Don't worry, you can first compose your circuit and obtain the size that
    // it will have. And then, generate the `PublicParameters` using as `max_size`
    // in the `setup` function params `composer.circuit_size().next_power_of_two()`.
    //
    // For this example we will asume that our circuit_size is between 2^10 & 2^11
    // gates, so we will basically use `max_size` as `2^11`.

    let public_params = PublicParameters::setup(1 << 11, &mut rand::thread_rng()).unwrap();

    // Now that we have our `PublicParameters` generated we will serialize them to
    // be able to use them on the next examples.
    //
    // This is something that you're not forced to do, you can generate a new
    // `PublicParameters` struct on every test you do, but if the size is big it
    // may take a little bit of time, instead, deserializing it might be a way faster and
    // easier.
    let ser_pub_params = bincode::serialize(&public_params).unwrap();

    fs::write("examples/.public_params.bin", &ser_pub_params).expect("Unable to write file");
}
