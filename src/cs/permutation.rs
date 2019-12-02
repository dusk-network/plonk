use super::constraint_system::{Variable, WireData, WireType};
use algebra::curves::PairingEngine;
use algebra::fields::PrimeField;
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use std::marker::PhantomData;

pub struct Permutation<E: PairingEngine> {
    _engine: PhantomData<E>,
    // maps variables to the wire data that they are assosciated with
    // To then later create the necessary permutations
    // XXX: the index will be the Variable reference, so it may be better to use a map to be more explicit here
    pub(crate) variable_map: Vec<Vec<WireData>>,
    pub(crate) sigmas: Vec<Vec<usize>>,
}

impl<E: PairingEngine> Permutation<E> {
    pub fn new() -> Permutation<E> {
        Permutation {
            _engine: PhantomData,
            variable_map: Vec::new(),
            sigmas: Vec::new(),
        }
    }
    pub fn add_variable_to_map(&mut self, a: Variable, b: Variable, c: Variable, n: usize) {
        let num_variables = self.variable_map.len();
        assert!(num_variables > a.0);
        assert!(num_variables > b.0);
        assert!(num_variables > c.0);

        let left: WireData = WireData::new(n, WireType::Left);
        let right: WireData = WireData::new(n, WireType::Right);
        let output: WireData = WireData::new(n, WireType::Output);

        // Map each variable to the wires it is assosciated with
        self.variable_map[a.0].push(left);
        self.variable_map[b.0].push(right);
        self.variable_map[c.0].push(output);
    }
    pub fn compute_sigma_polynomials(
        &mut self,
        n: usize,
        domain: &EvaluationDomain<E::Fr>,
    ) -> (Polynomial<E::Fr>, Polynomial<E::Fr>, Polynomial<E::Fr>) {
        // Compute sigma mappings
        self.compute_sigma_permutations(n);

        // convert the sigma mappings to polynomials
        let left_sigma = self.compute_permutation_lagrange(&self.sigmas[0], domain);
        let right_sigma = self.compute_permutation_lagrange(&self.sigmas[1], domain);
        let out_sigma = self.compute_permutation_lagrange(&self.sigmas[2], domain);

        let left_sigma_poly = Polynomial::from_coefficients_vec(domain.ifft(&left_sigma));
        let right_sigma_poly = Polynomial::from_coefficients_vec(domain.ifft(&right_sigma));
        let out_sigma_poly = Polynomial::from_coefficients_vec(domain.ifft(&out_sigma));

        (left_sigma_poly, right_sigma_poly, out_sigma_poly)
    }

    fn compute_permutation_lagrange(
        &self,
        sigma_mapping: &[usize],
        domain: &EvaluationDomain<E::Fr>,
    ) -> Vec<E::Fr> {
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from_repr_raw(13.into());

        let lagrange_poly = domain
            .elements()
            .zip(sigma_mapping.iter())
            .map(|(w, encoded_wire)| {
                let wire_type: WireType = encoded_wire.into();

                match wire_type {
                    WireType::Left => w,
                    WireType::Right => w * &k1,
                    WireType::Output => w * &k2,
                }
            })
            .collect();
        lagrange_poly
    }

    // Computes sigma_1, sigma_2 and sigma_3 permutations
    pub(super) fn compute_sigma_permutations(&mut self, n: usize) {
        let sigma_1: Vec<_> = (0 + WireType::Left as usize..n + WireType::Left as usize).collect();
        let sigma_2: Vec<_> =
            (0 + WireType::Right as usize..n + WireType::Right as usize).collect();
        let sigma_3: Vec<_> =
            (0 + WireType::Output as usize..n + WireType::Output as usize).collect();

        assert_eq!(sigma_1.len(), n);
        assert_eq!(sigma_2.len(), n);
        assert_eq!(sigma_3.len(), n);

        self.sigmas = vec![sigma_1, sigma_2, sigma_3];

        for variable in self.variable_map.iter() {
            // Gets the data for each wire assosciated with this variable
            for (wire_index, current_wire) in variable.iter().enumerate() {
                // Fetch index of the next wire, if it is the last element
                // We loop back around to the beginning
                let next_index = match wire_index == variable.len() - 1 {
                    true => 0,
                    false => wire_index + 1,
                };

                // Fetch the next wire
                let next_wire = &variable[next_index];

                // Map current wire to the next wire
                // XXX: We could probably split up sigmas and do a match statement here
                // Or even better, to avoid the allocations when defining sigma_1,sigma_2 and sigma_3 we can use a better more explicit encoding
                self.sigmas[current_wire.wire_type as usize >> 30][current_wire.gate_index] =
                    next_wire.gate_index + next_wire.wire_type as usize;
            }
        }
    }
}
