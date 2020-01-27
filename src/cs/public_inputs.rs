use algebra::curves::PairingEngine;
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use std::marker::PhantomData;

/// Computation for the public inputs. Utilising the Lagrange polynomials,
/// and summing them all. For vectors of length n, where n is the number
/// of elements in the preselector polynomial vector. We also compute
/// the sum of the witness polynomials, which are notably seperate from
/// the witnesses that are private.

pub struct PInputsToolkit<E: PairingEngine> {
    _engine: PhantomData<E>,
}
impl<E: PairingEngine> PInputsToolkit<E> {
    pub fn new() -> Self {
        PInputsToolkit {
            _engine: PhantomData,
        }
    }
    pub fn compute_pi_poly(&self, w_i: &Vec<E::Fr>) -> Polynomial<E::Fr> {
        let domain = EvaluationDomain::new(w_i.len()).unwrap();
        Polynomial::from_coefficients_vec(domain.ifft(w_i))
    }
    pub fn evaluate_pi_poly(&self, w_i: &Polynomial<E::Fr>, point: &E::Fr) -> E::Fr {
        w_i.evaluate(*point)
    }
}
