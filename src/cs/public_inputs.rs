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
/// and summing them all. We also compute the sum of the witness
/// polynomials, which are notably seperate from the witnesses that are private.

pub struct PIInputsToolKit<E: PairingEngine> {
    _engine: PhantomData<E>,
}
impl<E: PairingEngine> PIInputsToolKit<E> {
    pub fn new() -> Self {
        PIInputsToolKit {
            _engine: PhantomData,
        }
    }

    // Generates the Public Inputs polynomial PI(X) from
    // a PreProcessedCircuit and the Public Input coeficients.
    //
    // # Panics
    // If the degree of any of the selector polynomials is = 0.
    pub fn gen_public_inputs_poly(
        &self,
        prep_circ: &PreProcessedCircuit<E>,
        pub_inputs: &Vec<E::Fr>,
    ) -> Polynomial<E::Fr> {
        assert!(prep_circ.qm_poly().len() > 0);
        // Get Lagrange polys.
        let lagrange_polys = prep_circ.compute_n_lagrange_polys();
        // Get PI negated factors as 0 degree polynomials
        let neg_inputs_as_polys: Vec<Polynomial<E::Fr>> = pub_inputs
            .into_iter()
            .map(|field_elem| -*field_elem)
            .map(|neg_field| Polynomial::from_coefficients_slice(&[neg_field]))
            .collect();
        // Compute `-x_i * L_i(X)` vector
        let prod_poly: Vec<Polynomial<E::Fr>> = lagrange_polys
            .into_par_iter()
            .zip(neg_inputs_as_polys.into_par_iter())
            .map(|(xi, li_x)| &xi * &li_x)
            .collect();
        // Sum up all of the product polys and return the result.
        let mut res = Polynomial::zero();
        for item in prod_poly {
            res = &res + &item;
        }
        res
    }
}
