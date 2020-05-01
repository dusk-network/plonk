//! PLONK is a ZK proving scheme which relies upon the use
//! of a Trusted Setup, which is universal and updateable.
//!
//! This plonk crate comes with a commitment scheme module,
//! which is already implemented, so performing any tests,
//! for the preprocessing, proving or verifying procedures
//! which are used in PLONK is automatic.
//!
//! To be precise, plonk comes with the `KZG10` polynomial
//! commitment scheme implemented on it. Which appart of other
//! functionalities allows us to setup "testing" or "debuging"
//! Trusted Setups (identified as `PublicParameters` by this repo).
//! With this, end-users are able to perform it's Prove&Verify tests
//! without needing to compute a "real Trusted Setup".
//!
//! **DO NOT USE** `PublicParameters` as you Trusted Setups in production
//! since they require complex Multi-Party computation processes
//! to be set up in a secure and correct way.
//!
//! ## Why do we care about that?
//!
//! Well, basically to be able to generate `Proof`s, we need to be able to
//! commit our polynomials and for that, we need to make use of a Trusted Setup.
//! This is used alongside a polynomial commitment scheme that allow us to generate
//! the structure to be used within PLONK.
//!
//! In the following example, we will see how the how to generate a Trusted Setup, represented
//! by PLONK's `PublicParameters` data structure to then be able to generate
//! `Proof`s and `PreProcessedCircuit`s, as well as verify these `Proof`s.

extern crate bincode;
extern crate dusk_plonk;
extern crate rand;

use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
use std::fs;

fn main() -> () {
    // First of all we generate our `PublicParameters` data structure.
    // NOTE that we need to specify the `size` of them.
    //
    // This `size` is usually set as the next_power_of_two of the `CIRCUIT_SIZE`
    // that we are expecting to have.
    //
    // Don't worry, you can always first compose your circuit and obtain the size that
    // it will have. Following on from this, you generate the `PublicParameters` using
    // as `max_size`, in the `setup` function params `composer.circuit_size().next_power_of_two()`.
    //
    // For this example we will assume that our circuit_size is between 2^10 & 2^11
    // gates, so we will basically use `max_size` as `2^11`.

    let public_params = PublicParameters::setup(1 << 11, &mut rand::thread_rng()).unwrap();

    // Now that we have our `PublicParameters` generated, we will serialize them so that
    // they can be used for the next examples.
    //
    // This is something that you're not forced to do, you can generate a new set of
    // `PublicParameters` struct on every test you do, but if the size is large then it
    // may take a little bit of time. Therefore, deserializing it might be a way faster and
    // easier.
    let ser_pub_params = bincode::serialize(&public_params).unwrap();

    fs::write("examples/.public_params.bin", &ser_pub_params).expect("Unable to write file");
}
