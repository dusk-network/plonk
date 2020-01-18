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

    pub fn compute_n_lagrange_polys(&self, size: usize) -> Vec<Polynomial<E::Fr>> {
        use ff_fft::{DenseOrSparsePolynomial, SparsePolynomial};
        use std::str::FromStr;
        // Compute the denominator.
        let numerator: DenseOrSparsePolynomial<E::Fr> =
            SparsePolynomial::from_coefficients_slice(&[(0, -E::Fr::one()), (size, E::Fr::one())])
                .into();

        let denominators: Vec<DenseOrSparsePolynomial<E::Fr>> = {
            let mut den: Vec<DenseOrSparsePolynomial<E::Fr>> = Vec::default();
            for i in 0..size {
                den.push(
                    SparsePolynomial::from_coefficients_slice(&[
                        (1, E::Fr::one()),
                        // Weird, however, `from_repr` and `from` are not working for this implementation.
                        (0, -E::Fr::from_str(&format!("{}", i)).ok().unwrap()),
                    ])
                    .into(),
                );
            }
            den
        };
        let res: Vec<Polynomial<E::Fr>> = denominators
            .into_iter()
            .map(|den| numerator.divide_with_q_and_r(&den).unwrap().0)
            .collect();
        res
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
        let lagrange_polys = self.compute_n_lagrange_polys(prep_circ.qm_poly().len());
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

mod tests {
    use super::*;
    use crate::cs::public_inputs::PIInputsToolKit;
    use algebra::curves::bls12_381::Bls12_381 as E;
    use algebra::fields::bls12_381::Fr;
    #[test]
    fn first_lagrange_poly() {
        let pi_tool: PIInputsToolKit<E> = PIInputsToolKit::new();
        let first_lag = pi_tool.compute_n_lagrange_polys(1usize);
        println!("{:?}", first_lag);
    }
}
