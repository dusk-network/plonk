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
//! In this example we will create an easy circuit. It will basically try to
//! prove that we know two numbers which it's XOR is a boolean result [0,1].

extern crate bincode;
extern crate plonk;

use bicode;
use bls12_381::{G1Affine, Scalar};
use plonk::constraint_system::{
    standard::{Composer, StandardComposer},
    PreProcessedCircuit,
};

fn main() {}
