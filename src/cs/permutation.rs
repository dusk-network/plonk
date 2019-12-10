use super::constraint_system::{Variable, WireData, WireType};
use crate::transcript::TranscriptProtocol;
use algebra::UniformRand;
use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use itertools::izip;
use rand_core::{CryptoRng, RngCore};
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
    ) -> (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>) {
        // Compute sigma mappings
        self.compute_sigma_permutations(n);

        // convert the sigma mappings to polynomials
        let left_sigma = self.compute_permutation_lagrange(&self.sigmas[0], domain);
        let right_sigma = self.compute_permutation_lagrange(&self.sigmas[1], domain);
        let out_sigma = self.compute_permutation_lagrange(&self.sigmas[2], domain);

        (
            domain.ifft(&left_sigma),
            domain.ifft(&right_sigma),
            domain.ifft(&out_sigma),
        )
    }

    pub(crate) fn compute_permutation_poly<R, I>(
        &self,
        n: usize,
        domain: &EvaluationDomain<E::Fr>,
        transcript: &mut dyn TranscriptProtocol<E>,
        mut rng: &mut R,
        w_l: I,
        w_r: I,
        w_o: I,
        left_sigma_poly: &[E::Fr],
        right_sigma_poly: &[E::Fr],
        out_sigma_poly: &[E::Fr],
    ) -> (Polynomial<E::Fr>, E::Fr, E::Fr)
    where
        I: Iterator<Item = E::Fr>,
        R: RngCore + CryptoRng,
    {
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from_repr_raw(13.into());

        // Compute challenges
        let beta = transcript.challenge_scalar(b"beta");
        let gamma = transcript.challenge_scalar(b"gamma");

        // Compute beta * sigma polynomials
        let beta_left_sigma = left_sigma_poly.iter().map(|sigma| *sigma * &beta);
        let beta_right_sigma = right_sigma_poly.iter().map(|sigma| *sigma * &beta);
        let beta_out_sigma = out_sigma_poly.iter().map(|sigma| *sigma * &beta);

        // Compute beta * roots
        let common_roots_iter = domain.elements().map(|root| root * &beta);

        // Compute beta * roots * k1
        let beta_roots_k1 = domain.elements().map(|root| beta * &root * &k1);

        // Compute beta * roots * k2
        let beta_roots_k2 = domain.elements().map(|root| beta * &root * &k2);

        // Compute left_wire + gamma
        let wL_gamma = w_l.map(|w_L| w_L + &gamma);

        // Compute right_wire + gamma
        let wR_gamma = w_r.map(|w_R| w_R + &gamma);

        // Compute out_wire + gamma
        let wO_gamma = w_o.map(|w_O| w_O + &gamma);

        // Compute 6 acumulator components
        let mut acumulator_components_without_l1 = izip!(
            wL_gamma,
            wR_gamma,
            wO_gamma,
            common_roots_iter,
            beta_roots_k1,
            beta_roots_k2,
            beta_left_sigma,
            beta_right_sigma,
            beta_out_sigma,
        )
        .map(
            |(
                w_l_gamma,
                w_r_gamma,
                w_o_gamma,
                beta_root,
                beta_root_k1,
                beta_root_k2,
                beta_left_sigma,
                beta_right_sigma,
                beta_out_sigma,
            )| {
                // w_j + beta * root^j-1 + gamma
                let AC1 = w_l_gamma + &beta_root;

                // w_{n+j} + beta * k1 * root^j-1 + gamma
                let AC2 = w_r_gamma + &beta_root_k1;

                // w_{2n+j} + beta * k2 * root^j-1 + gamma
                let AC3 = w_o_gamma + &beta_root_k2;

                // 1 / w_j + beta * sigma(j) + gamma
                let mut AC4 = w_l_gamma + &beta_left_sigma;
                AC4.inverse_in_place().unwrap();

                // 1 / w_{n+j} + beta * k1 * sigma(n+j) + gamma
                let mut AC5 = w_r_gamma + &beta_right_sigma;
                AC5.inverse_in_place().unwrap();

                // 1 / w_{2n+j} + beta * k2 * sigma(2n+j) + gamma
                let mut AC6 = w_o_gamma + &beta_out_sigma;
                AC6.inverse_in_place().unwrap();

                (AC1, AC2, AC3, AC4, AC5, AC6)
            },
        );

        // Remove the last element and prepend ones to the beginning of each acumulator to signify L_1(x)
        let acumulator_components = std::iter::once((
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
        ))
        .chain(acumulator_components_without_l1.take(n - 1));

        // XXX: We could put this in with the previous iter method, but it will not be clear
        // Multiply each component of the accumulators
        // A simplified example is the following:
        // A1 = [1,2,3,4]
        // result = [1, 1*2, 1*2*3, 1*2*3*4]
        let mut prev = (
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
        );
        let product_acumulated_components = acumulator_components.map(move |current_component| {
            prev.0 *= &current_component.0;
            prev.1 *= &current_component.1;
            prev.2 *= &current_component.2;
            prev.3 *= &current_component.3;
            prev.4 *= &current_component.4;
            prev.5 *= &current_component.5;

            prev
        });

        // right now we basically have 6 acumulators of the form:
        // A1 = [a1, a1 * a2, a1*a2*a3,...]
        // A2 = [b1, b1 * b2, b1*b2*b3,...]
        // A3 = [c1, c1 * c2, c1*c2*c3,...]
        // ... and so on
        // We want:
        // [a1*b*c1, a1 * a2 *b1 * b2 * c1 * c2,...]
        let mut prev = E::Fr::one();
        let z: Vec<_> = product_acumulated_components
            .map(move |current_component| {
                prev *= &current_component.0;
                prev *= &current_component.1;
                prev *= &current_component.2;
                prev *= &current_component.3;
                prev *= &current_component.4;
                prev *= &current_component.5;

                prev
            })
            .collect();

        assert_eq!(n, z.len());

        // Compute permutation polynomail and blind it
        let mut z_poly = Polynomial::from_coefficients_vec(domain.ifft(&z));

        // Compute blinder polynomial
        let b_7 = E::Fr::rand(&mut rng);
        let b_8 = E::Fr::rand(&mut rng);
        let b_9 = E::Fr::rand(&mut rng);

        let z_blinder =
            Polynomial::from_coefficients_slice(&[b_9, b_8, b_7]).mul_by_vanishing_poly(*domain);

        let z_poly_blinded = &z_poly + &z_blinder;

        (z_poly_blinded, beta, gamma)
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
