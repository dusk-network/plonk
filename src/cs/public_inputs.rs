use crate::cs::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use rayon::iter::*;
use std::marker::PhantomData;

/// Computation for the public inputs. Utilising the Lagrange polynomials,
/// and summing them all. For vectors of length n, where n is the number 
/// of elements in the preselector polynomial vector. We also compute 
/// the sum of the witness polynomials, which are notably seperate from 
/// the witnesses that are private.

pub struct PIInputsToolKit<E: PairingEngine> {
    _engine: PhantomData<E>,
}
impl<E: PairingEngine> PIInputsToolKit<E> {
    pub fn new() -> Self {
        PIInputsToolKit {
            _engine: PhantomData, 
        }
    }


    fn compute_public_inputs() {
    use algebra::UniformRand;
    let n = prep_circ.qm_poly().len();
    let domain = EvaluationDomain::new(n).unwrap();
    let w_i = vec![n];

    let z = Fr::rand(&mut rand::thread_rng());
    let l_coeffs = domain.evaluate_all_lagrange_coefficients(z);
    assert_eq!(l_coeffs.len(), n);

    let mut sum = Fr::zero();
    for (x, y) in w_i.clone().into_iter().zip(l_coeffs) {
        let partial_sum = x * &y;
        sum = sum + &partial_sum;    
    }

    let w_i_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_i));
    let w_i_eval = w_i_poly.evaluate(z);
    assert_eq!(w_i_eval, sum);
}


mod tests {
    use super::*;
    use crate::cs::public_inputs::PIInputsToolKit;
    use algebra::curves::bls12_381::Bls12_381 as E;
    use algebra::fields::bls12_381::Fr;
}
