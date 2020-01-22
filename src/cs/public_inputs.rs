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
    pub fn compute_pi_poly(&self, w_i: &Vec<E::Fr>) -> Polynomial<E::Fr> {
        let domain = EvaluationDomain::new(w_i.len()).unwrap();
        Polynomial::from_coefficients_vec(domain.ifft(w_i))
    }
    pub fn evaluate_pi_poly(&self, w_i: &Polynomial<E::Fr>, point: &E::Fr) -> E::Fr {
        w_i.evaluate(*point)
    }
}

mod tests {
    use super::*;
    use crate::cs::public_inputs::PIInputsToolKit;
    use algebra::curves::bls12_381::Bls12_381 as E;
    use algebra::fields::bls12_381::Fr;

    #[test]
    fn test_pi_poly_comp_eval() {
        use algebra::UniformRand;

        let n = 4;
        let domain = EvaluationDomain::new(4).unwrap();
        let w_i = vec![Fr::from(4u8), Fr::from(5u8), Fr::from(6u8), Fr::from(7u8)];

        let z = Fr::rand(&mut rand::thread_rng());
        let l_coeffs = domain.evaluate_all_lagrange_coefficients(z);
        assert_eq!(l_coeffs.len(), 4);

        let mut sum = Fr::zero();
        for (x, y) in w_i.clone().into_iter().zip(l_coeffs) {
            let partial_sum = x * &y;
            sum = sum + &partial_sum;
        }
        let pi_toolkit: PIInputsToolKit<E> = PIInputsToolKit::new();
        let p_i_x = pi_toolkit.compute_pi_poly(&w_i);
        let p_i_z = pi_toolkit.evaluate_pi_poly(&p_i_x, &z);
        assert_eq!(p_i_z, sum);
    }
}
