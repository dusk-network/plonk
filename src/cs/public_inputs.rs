use crate::cs::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use std::marker::PhantomData;

/// Computation for the public inputs. Utilising the Lagrange polynomials, 
/// and summing all of them bar the first. We also compute the sum of the witness 
/// polynomials, which are notably seperate from the witnesses that are pruvate
/// public inout is separate from witnessess that are private

pub fn compute_langrange_polynomial