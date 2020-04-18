//! In order to construct a `Proof`, we first need to build the circuit
//! over which it operates and it's defined.
//!
//! Building that circuit is something we can achieve by using PLONK's
//! `StandardComposer`. It is a struct which has implemented functions to
//! allow the end-user represent the logic of the circuit by adding to it
//! the operations that need to be performed with the witnesses and the Public
//! Inputs.
//!
//! The second step to be able to generate the `Proof` is to buid a
//! `PreProcessedCircuit` structure, which is a pure definition of the
//! logic of the circuit we've build with the help of the `StandardComposer`
//! previously.
//! This, is achieved by ordering to our `StandardComposer` to preprocess
//! the logic that we've implemented with it returning to us a
//! `PreProcessedCircuit` struct which holds the info of the wire-selector
//! polynomials (the info of the polynomials that describe the operations that
//! we perform in our circuit).
//!
//!
//! We will show in this file how we can construct circuits using PLONKs'
//! `StandardComposer` and then, how to obtain a `PreProcessedCircuit`
//! struct which holds the description of the circuit we've designed
//! to then be able to generate a `Proof` with it.
//!
//! In this example we will create an easy circuit:
//! - We know 6 values A, B, C, D, E & F.
//! - we will prove that this 6 numbers satisfy that `A * B ^ C + D == 1`.
//! - We have a public input which is 1.
//! - The circuit will perform: `((A + B ^ C + D) is bool) and also == 1` 
//! 
//! `Composers` work with `Variables` instead of the `Scalar` values directly
//! when we want to use that `Scalar`s as witness values (secret).
//! `Variables` are some sort of references linked to the original `Scalar` value
//! inside of the `StandardComposer`'s memory.
//! So every time we want to use a new secret value, we need to obtain a `Variable`
//! from it's original value so it is then marked as "secret".
//! 
//! For the rest of the circuit describers such as the selector polynomials (which
//! define the operations that we do and how we "scale" hidden values) we simply use
//! "Scalar"s since they're not secret nor hidden to anyone. 
//! Remember that both `Prover` and `Verifier` have the same view of the circuit description
//! but not for the witness values.

extern crate bincode;
extern crate plonk;

use bicode;
use bls12_381::{G1Affine, Scalar};
use plonk::constraint_system::{
    standard::{Composer, StandardComposer},
    PreProcessedCircuit,
};

fn main() {
    // First of all, let's create our new composer. If we know the size that it will
    // have, calling `with expected size` can decrease the re-allocs and so improve
    // the performance.
    let mut composer = StandardComposer::with_expected_size(1 << 10);

    // Then we generate our `Scalar` values A, B, C, D that we want to prove
    // that satisfy the aformentioned properties.
    let a_scalar = Scalar::from(4u64)
    let b_scalar = Scalar::from(6u64)
    let c_scalar = Scalar::from(3u64)
    let d_scalar = Scalar::from(8u64)
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
    // of providing the result or not, we will go with the second option.

    let a_plus_b = composer.big_add_gate(a: Variable, b: Variable, c: Variable, d: Variable, q_l: Scalar, q_r: Scalar, q_o: Scalar, q_4: Scalar, q_c: Scalar, pi: Scalar)
}
