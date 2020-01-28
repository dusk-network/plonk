use super::constraint_system::{Variable, WireData, WireType};
use crate::transcript::TranscriptProtocol;
use merlin::Transcript;

use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use itertools::izip;
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use std::marker::PhantomData;

pub struct Permutation<E: PairingEngine> {
    _engine: PhantomData<E>,

    // These are the actual variable values
    // N.B. They should not be exposed to the end user once added into the composer
    variables: Vec<E::Fr>,

    // maps variables to the wire data that they are assosciated with
    // To then later create the necessary permutations
    // XXX: the index will be the Variable reference, so it may be better to use a map to be more explicit here
    pub(crate) variable_map: Vec<Vec<WireData>>,

    left_sigma_mapping: Option<Vec<E::Fr>>,
    right_sigma_mapping: Option<Vec<E::Fr>>,
    out_sigma_mapping: Option<Vec<E::Fr>>,
}

impl<E: PairingEngine> Permutation<E> {
    /// Creates a permutation struct which will ultimately create the permutation polynomial
    pub fn new() -> Permutation<E> {
        Permutation::with_capacity(0)
    }
    pub fn with_capacity(expected_size: usize) -> Permutation<E> {
        Permutation {
            _engine: PhantomData,
            variables: Vec::with_capacity(expected_size),
            variable_map: Vec::with_capacity(expected_size),

            left_sigma_mapping: None,
            right_sigma_mapping: None,
            out_sigma_mapping: None,
        }
    }
    /// Adds a Scalar into the system and creates a new variable for it
    pub fn new_variable(&mut self, s: E::Fr) -> Variable {
        // Push scalar into the system
        self.variables.push(s);

        // Add an empty space for it in the variable map
        self.variable_map.push(Vec::new());

        assert_eq!(self.variables.len(), self.variable_map.len());

        // Return reference to scalar
        let index = self.variables.len() - 1;
        Variable(index)
    }
    /// Checks that the variables are valid by determining if they have been added to the system
    fn valid_variables(&self, variables: &[Variable]) -> bool {
        let num_variables = self.variable_map.len();
        for variable in variables.iter() {
            let index = variable.0;
            if index >= num_variables {
                return false;
            }
        }
        return true;
    }
    /// Maps a set of variables (a,b,c) to a set of Wires (left, right, out) where `n` is the gate index
    pub fn add_variable_to_map(&mut self, a: Variable, b: Variable, c: Variable, n: usize) {
        assert!(self.valid_variables(&[a, b, c]));

        let left: WireData = WireData::new(n, WireType::Left);
        let right: WireData = WireData::new(n, WireType::Right);
        let output: WireData = WireData::new(n, WireType::Output);

        // Map each variable to the wires it iscomp assosciated with
        // This essentially tells us that:
        // Variable `a` is being used in the n'th gate as a left wire
        // Variable `b` is being used in the n'th gate as a right wire
        // Variable `c` is being used in the n'th gate as an output wire
        self.variable_map[a.0].push(left);
        self.variable_map[b.0].push(right);
        self.variable_map[c.0].push(output);
    }
    /// Convert variables to their actual Scalars
    pub(super) fn witness_vars_to_scalars(
        &self,
        w_l: &[Variable],
        w_r: &[Variable],
        w_o: &[Variable],
    ) -> (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>) {
        // XXX: We could probably chuck this check, as it will fail if variables are not valid
        assert!(
            self.valid_variables(w_l) && self.valid_variables(w_r) && self.valid_variables(w_o)
        );

        (
            w_l.par_iter().map(|var| self.variables[var.0]).collect(),
            w_r.par_iter().map(|var| self.variables[var.0]).collect(),
            w_o.par_iter().map(|var| self.variables[var.0]).collect(),
        )
    }

    // Performs shift by one permutation and computes sigma_1, sigma_2 and sigma_3 permutations from the variable maps
    pub(super) fn compute_sigma_permutations(&mut self, n: usize) -> [Vec<usize>; 3] {
        let sigma_1: Vec<_> = (0 + WireType::Left as usize..n + WireType::Left as usize).collect();
        let sigma_2: Vec<_> =
            (0 + WireType::Right as usize..n + WireType::Right as usize).collect();
        let sigma_3: Vec<_> =
            (0 + WireType::Output as usize..n + WireType::Output as usize).collect();

        assert_eq!(sigma_1.len(), n);
        assert_eq!(sigma_2.len(), n);
        assert_eq!(sigma_3.len(), n);

        let mut sigmas = [sigma_1, sigma_2, sigma_3];

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
                sigmas[current_wire.wire_type as usize >> 30][current_wire.gate_index] =
                    next_wire.gate_index + next_wire.wire_type as usize;
            }
        }

        sigmas
    }

    fn compute_permutation_lagrange(
        &self,
        sigma_mapping: &[usize],
        domain: &EvaluationDomain<E::Fr>,
    ) -> Vec<E::Fr> {
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from(13.into());

        let roots: Vec<_> = domain.elements().collect();

        let lagrange_poly: Vec<E::Fr> = sigma_mapping
            .iter()
            .map(|x| {
                // XXX: We can probably just pass around WireData and then we no longer need to do the conversion here
                let wire_data: WireData = x.into();
                let root = &roots[wire_data.gate_index];
                match wire_data.wire_type {
                    WireType::Left => *root,
                    WireType::Right => k1 * root,
                    WireType::Output => k2 * root,
                }
            })
            .collect();

        lagrange_poly
    }

    pub fn compute_sigma_polynomials(
        &mut self,
        n: usize,
        domain: &EvaluationDomain<E::Fr>,
    ) -> (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>) {
        // Compute sigma mappings
        let sigmas = self.compute_sigma_permutations(n);

        assert_eq!(sigmas[0].len(), n);
        assert_eq!(sigmas[1].len(), n);
        assert_eq!(sigmas[2].len(), n);

        // define the sigma permutations using two non quadratic residues
        let left_sigma = self.compute_permutation_lagrange(&sigmas[0], domain);
        let right_sigma = self.compute_permutation_lagrange(&sigmas[1], domain);
        let out_sigma = self.compute_permutation_lagrange(&sigmas[2], domain);

        let left_sigma_coeffs = domain.ifft(&left_sigma);
        let right_sigma_coeffs = domain.ifft(&right_sigma);
        let out_sigma_coeffs = domain.ifft(&out_sigma);

        self.left_sigma_mapping = Some(left_sigma);
        self.right_sigma_mapping = Some(right_sigma);
        self.out_sigma_mapping = Some(out_sigma);

        (left_sigma_coeffs, right_sigma_coeffs, out_sigma_coeffs)
    }

    pub(crate) fn compute_permutation_poly<R>(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        mut rng: &mut R,
        w_l: &[E::Fr],
        w_r: &[E::Fr],
        w_o: &[E::Fr],
        (beta, gamma): &(E::Fr, E::Fr),
    ) -> Vec<E::Fr>
    where
        R: RngCore + CryptoRng,
    {
        let z_evaluations = self.compute_fast_permutation_poly(domain, w_l, w_r, w_o, beta, gamma);
        domain.ifft(&z_evaluations)
    }

    fn compute_slow_permutation_poly<I>(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        w_l: I,
        w_r: I,
        w_o: I,
        beta: &E::Fr,
        gamma: &E::Fr,
    ) -> (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>)
    where
        I: Iterator<Item = E::Fr>,
    {
        let n = domain.size();

        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from(13.into());

        let left_sigma_mapping = self.left_sigma_mapping.as_ref().unwrap();
        let right_sigma_mapping = self.right_sigma_mapping.as_ref().unwrap();
        let out_sigma_mapping = self.out_sigma_mapping.as_ref().unwrap();

        // Compute beta * sigma polynomials
        let beta_left_sigma_iter = left_sigma_mapping.iter().map(|sigma| *sigma * beta);
        let beta_right_sigma_iter = right_sigma_mapping.iter().map(|sigma| *sigma * beta);
        let beta_out_sigma_iter = out_sigma_mapping.iter().map(|sigma| *sigma * beta);

        // Compute beta * roots
        let beta_roots_iter = domain.elements().map(|root| root * beta);

        // Compute beta * roots * k1
        let beta_roots_k1_iter = domain.elements().map(|root| (k1 * beta) * &root);

        // Compute beta * roots * k2
        let beta_roots_k2_iter = domain.elements().map(|root| (k2 * beta) * &root);

        // Compute left_wire + gamma
        let wL_gamma: Vec<_> = w_l.map(|w| w + gamma).collect();

        // Compute right_wire + gamma
        let wR_gamma: Vec<_> = w_r.map(|w| w + gamma).collect();

        // Compute out_wire + gamma
        let wO_gamma: Vec<_> = w_o.map(|w| w + gamma).collect();

        let mut numerator_partial_components: Vec<E::Fr> = Vec::with_capacity(n);
        let mut denominator_partial_components: Vec<E::Fr> = Vec::with_capacity(n);

        let mut numerator_coefficients: Vec<E::Fr> = Vec::with_capacity(n);
        let mut denominator_coefficients: Vec<E::Fr> = Vec::with_capacity(n);

        // First element in both of them is one
        numerator_coefficients.push(E::Fr::one());
        denominator_coefficients.push(E::Fr::one());

        // Compute numerator coefficients
        for (w_l_gamma, w_r_gamma, w_o_gamma, beta_root, beta_root_k1, beta_root_k2) in izip!(
            wL_gamma.iter(),
            wR_gamma.iter(),
            wO_gamma.iter(),
            beta_roots_iter,
            beta_roots_k1_iter,
            beta_roots_k2_iter,
        ) {
            // (w_L + beta * root + gamma)
            let prod_a = beta_root + w_l_gamma;

            // (w_R + beta * root * k_1 + gamma)
            let prod_b = beta_root_k1 + w_r_gamma;

            // (w_O + beta * root * k_2 + gamma)
            let prod_c = beta_root_k2 + w_o_gamma;

            let mut prod = prod_a * &prod_b;
            prod = prod * &prod_c;

            numerator_partial_components.push(prod);

            prod = prod * numerator_coefficients.last().unwrap();

            numerator_coefficients.push(prod);
        }

        // Compute denominator coefficients
        for (w_l_gamma, w_r_gamma, w_o_gamma, beta_left_sigma, beta_right_sigma, beta_out_sigma) in izip!(
            wL_gamma,
            wR_gamma,
            wO_gamma,
            beta_left_sigma_iter,
            beta_right_sigma_iter,
            beta_out_sigma_iter,
        ) {
            // (w_L + beta * root + gamma)
            let prod_a = beta_left_sigma + &w_l_gamma;

            // (w_R + beta * root * k_1 + gamma)
            let prod_b = beta_right_sigma + &w_r_gamma;

            // (w_O + beta * root * k_2 + gamma)
            let prod_c = beta_out_sigma + &w_o_gamma;

            let mut prod = prod_a * &prod_b;
            prod = prod * &prod_c;

            denominator_partial_components.push(prod);

            let last_element = denominator_coefficients.last().unwrap();

            prod = prod * last_element;

            denominator_coefficients.push(prod);
        }

        assert_eq!(denominator_coefficients.len(), n + 1);
        assert_eq!(numerator_coefficients.len(), n + 1);

        // Check that n+1'th elements are equal (taken from proof)
        let a = numerator_coefficients.last().unwrap();
        assert_ne!(a, &E::Fr::zero());
        let b = denominator_coefficients.last().unwrap();
        assert_ne!(b, &E::Fr::zero());
        assert_eq!(*a / b, E::Fr::one());

        // Remove those extra elements
        numerator_coefficients.remove(n);
        denominator_coefficients.remove(n);

        // Combine numerator and denominator

        let mut z_coefficients: Vec<E::Fr> = Vec::with_capacity(n);
        for (numerator, denominator) in numerator_coefficients
            .iter()
            .zip(denominator_coefficients.iter())
        {
            z_coefficients.push(*numerator / &denominator);
        }
        assert_eq!(z_coefficients.len(), n);

        (
            z_coefficients,
            numerator_partial_components,
            denominator_partial_components,
        )
    }

    fn compute_fast_permutation_poly(
        &self,
        domain: &EvaluationDomain<E::Fr>,
        w_l: &[E::Fr],
        w_r: &[E::Fr],
        w_o: &[E::Fr],
        beta: &E::Fr,
        gamma: &E::Fr,
    ) -> Vec<E::Fr> {
        let n = domain.size();

        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from(13.into());
        // Compute beta * roots
        let common_roots: Vec<_> = domain.elements().map(|root| root * beta).collect();

        use rayon::iter::ParallelIterator;
        let left_sigma_mapping = self.left_sigma_mapping.as_ref().unwrap();
        let right_sigma_mapping = self.right_sigma_mapping.as_ref().unwrap();
        let out_sigma_mapping = self.out_sigma_mapping.as_ref().unwrap();

        // Compute beta * sigma polynomials
        let beta_left_sigmas: Vec<_> = left_sigma_mapping
            .par_iter()
            .map(|sigma| *sigma * beta)
            .collect();
        let beta_right_sigmas: Vec<_> = right_sigma_mapping
            .par_iter()
            .map(|sigma| *sigma * beta)
            .collect();
        let beta_out_sigmas: Vec<_> = out_sigma_mapping
            .par_iter()
            .map(|sigma| *sigma * beta)
            .collect();

        // Compute beta * roots * k1
        let beta_roots_k1: Vec<_> = common_roots.par_iter().map(|x| *x * &k1).collect();

        // Compute beta * roots * k2
        let beta_roots_k2: Vec<_> = common_roots.par_iter().map(|x| *x * &k2).collect();

        // Compute left_wire + gamma
        let wL_gamma: Vec<_> = w_l.par_iter().map(|w_L| *w_L + gamma).collect();

        // Compute right_wire + gamma
        let wR_gamma: Vec<_> = w_r.par_iter().map(|w_R| *w_R + gamma).collect();

        // Compute out_wire + gamma
        let wO_gamma: Vec<_> = w_o.par_iter().map(|w_O| *w_O + gamma).collect();

        // Compute 6 acumulator components
        // Parallisable
        let mut acumulator_components_without_l1: Vec<_> = (
            wL_gamma,
            wR_gamma,
            wO_gamma,
            common_roots,
            beta_roots_k1,
            beta_roots_k2,
            beta_left_sigmas,
            beta_right_sigmas,
            beta_out_sigmas,
        )
            .into_par_iter()
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

                    // 1 / w_{n+j} + beta * sigma(n+j) + gamma
                    let mut AC5 = w_r_gamma + &beta_right_sigma;
                    AC5.inverse_in_place().unwrap();

                    // 1 / w_{2n+j} + beta * sigma(2n+j) + gamma
                    let mut AC6 = w_o_gamma + &beta_out_sigma;
                    AC6.inverse_in_place().unwrap();

                    (AC1, AC2, AC3, AC4, AC5, AC6)
                },
            )
            .collect();

        // Prepend ones to the beginning of each acumulator to signify L_1(x)
        let acumulator_components = std::iter::once((
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
        ))
        .chain(acumulator_components_without_l1);

        // XXX: We could put this in with the previous iter method, but it will not be clear
        // Actually, we should not because the first part is parallelisable, while this section is not
        // Multiply each component of the accumulators
        // A simplified example is the following:
        // A1 = [1,2,3,4]
        // result = [1, 1*2, 1*2*3, 1*2*3*4]
        // Non Parallisable
        let mut prev = (
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
            E::Fr::one(),
        );
        let product_acumulated_components: Vec<_> = acumulator_components
            .map(move |current_component| {
                prev.0 *= &current_component.0;
                prev.1 *= &current_component.1;
                prev.2 *= &current_component.2;
                prev.3 *= &current_component.3;
                prev.4 *= &current_component.4;
                prev.5 *= &current_component.5;

                prev
            })
            .collect();

        // right now we basically have 6 acumulators of the form:
        // A1 = [a1, a1 * a2, a1*a2*a3,...]
        // A2 = [b1, b1 * b2, b1*b2*b3,...]
        // A3 = [c1, c1 * c2, c1*c2*c3,...]
        // ... and so on
        // We want:
        // [a1*b1*c1, a1 * a2 *b1 * b2 * c1 * c2,...]
        // Parallisable
        let mut z: Vec<_> = product_acumulated_components
            .par_iter()
            .map(move |current_component| {
                let mut prev = E::Fr::one();
                prev *= &current_component.0;
                prev *= &current_component.1;
                prev *= &current_component.2;
                prev *= &current_component.3;
                prev *= &current_component.4;
                prev *= &current_component.5;

                prev
            })
            .collect();
        // Remove the last(n+1'th) element
        z.remove(n);

        assert_eq!(n, z.len());

        z
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381 as E;
    use algebra::fields::bls12_381::Fr;
    use algebra::UniformRand;
    use std::str::FromStr;
    #[test]
    fn test_permutation_format() {
        let mut perm: Permutation<E> = Permutation::new();

        let num_variables = 10;
        for i in 0..num_variables {
            let var = perm.new_variable(Fr::one());
            assert_eq!(var.0, i);
            assert_eq!(perm.variable_map.len(), i + 1);
            assert_eq!(perm.variables.len(), i + 1);
        }

        let var_one = perm.new_variable(Fr::one());
        let var_two = perm.new_variable(Fr::one() + &Fr::one());

        let gate_size = 100;
        for i in 0..gate_size {
            perm.add_variable_to_map(var_one, var_one, var_two, i);
        }

        // Check all gate_indices are valid
        for var in perm.variable_map.iter() {
            for wire in var.iter() {
                assert!(wire.gate_index < gate_size);
            }
        }
    }
    fn compute_identity_sigmas(n: usize) -> [Vec<Fr>; 3] {
        let domain = EvaluationDomain::new(n).unwrap();
        let sigma_1: Vec<_> = (0 + WireType::Left as usize..n + WireType::Left as usize).collect();
        let sigma_2: Vec<_> =
            (0 + WireType::Right as usize..n + WireType::Right as usize).collect();
        let sigma_3: Vec<_> =
            (0 + WireType::Output as usize..n + WireType::Output as usize).collect();

        let perm: Permutation<E> = Permutation::new();
        let sig_1 = perm.compute_permutation_lagrange(&sigma_1, &domain);
        let sig_2 = perm.compute_permutation_lagrange(&sigma_2, &domain);
        let sig_3 = perm.compute_permutation_lagrange(&sigma_3, &domain);

        [sig_1, sig_2, sig_3]
    }
    #[test]
    fn test_permutation_compute_sigmas_only_left_wires() {
        let mut perm: Permutation<E> = Permutation::new();

        let var_zero = perm.new_variable(Fr::zero());
        let var_one = perm.new_variable(Fr::one());
        let var_two = perm.new_variable(Fr::one() + &Fr::one());
        let var_three = perm.new_variable(Fr::one() + &Fr::one() + &Fr::one());
        let var_four = perm.new_variable(Fr::from(4 as u8));
        let var_five = perm.new_variable(Fr::from(5 as u8));
        let var_six = perm.new_variable(Fr::from(6 as u8));
        let var_seven = perm.new_variable(Fr::from(7 as u8));
        let var_eight = perm.new_variable(Fr::from(8 as u8));

        let num_wire_mappings = 4;

        // Add four wire mappings
        perm.add_variable_to_map(var_zero, var_zero, var_five, 0);
        perm.add_variable_to_map(var_zero, var_two, var_six, 1);
        perm.add_variable_to_map(var_zero, var_three, var_seven, 2);
        perm.add_variable_to_map(var_zero, var_four, var_eight, 3);

        /*

        var_zero = {L0, R0,L1,L2, L3}
        var_two = {R1}
        var_three = {R2}
        var_four = {R4}
        var_five = {01}
        var_six = {O2}
        var_seven = {O3}
        var_eight = {O4}

        Left_sigma = {R0, L2,L3, L0}
        Right_sigma = {L1, R1, R2, R3}
        Out_sigma = {O0, O1, O2, O3, O4}

        */

        let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
        let left_sigma = &sigmas[0];
        let right_sigma = &sigmas[1];
        let out_sigma = &sigmas[2];

        // Check the left sigma polynomial
        assert_eq!(left_sigma[0] - (WireType::Right as usize), 0);
        assert_eq!(left_sigma[1] - (WireType::Left as usize), 2);
        assert_eq!(left_sigma[2] - (WireType::Left as usize), 3);
        assert_eq!(left_sigma[3] - (WireType::Left as usize), 0);

        // Check the right sigma polynomial
        assert_eq!(right_sigma[0] - (WireType::Left as usize), 1);
        assert_eq!(right_sigma[1] - (WireType::Right as usize), 1);
        assert_eq!(right_sigma[2] - (WireType::Right as usize), 2);
        assert_eq!(right_sigma[3] - (WireType::Right as usize), 3);

        // Check the output sigma polynomial
        assert_eq!(out_sigma[0] - (WireType::Output as usize), 0);
        assert_eq!(out_sigma[1] - (WireType::Output as usize), 1);
        assert_eq!(out_sigma[2] - (WireType::Output as usize), 2);
        assert_eq!(out_sigma[3] - (WireType::Output as usize), 3);

        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let k1 = Fr::multiplicative_generator();
        let k2 = Fr::from(13u8);
        let w: Fr = domain.group_gen;
        let w_squared = w.pow(&[2 as u64]);
        let w_cubed = w.pow(&[3 as u64]);

        // check the left sigmas have been encoded properly
        // Left_sigma = {R0, L2,L3, L0}
        // Should turn into {1 * k1, w^2, w^3, 1}
        let encoded_left_sigma = perm.compute_permutation_lagrange(left_sigma, &domain);
        assert_eq!(encoded_left_sigma[0], Fr::one() * &k1);
        assert_eq!(encoded_left_sigma[1], w_squared);
        assert_eq!(encoded_left_sigma[2], w_cubed);
        assert_eq!(encoded_left_sigma[3], Fr::one());

        // check the right sigmas have been encoded properly
        // Right_sigma = {L1, R1, R2, R3}
        // Should turn into {w, w * k1, w^2 * k1, w^3 * k1}
        let encoded_right_sigma = perm.compute_permutation_lagrange(right_sigma, &domain);
        assert_eq!(encoded_right_sigma[0], w);
        assert_eq!(encoded_right_sigma[1], w * &k1);
        assert_eq!(encoded_right_sigma[2], w_squared * &k1);
        assert_eq!(encoded_right_sigma[3], w_cubed * &k1);

        // check the output sigmas have been encoded properly
        // Out_sigma = {O0, O1, O2, O3, O4}
        // Should turn into {1 * k2, w * k2, w^2 * k2, w^3 * k2}
        let encoded_output_sigma = perm.compute_permutation_lagrange(out_sigma, &domain);
        assert_eq!(encoded_output_sigma[0], Fr::one() * &k2);
        assert_eq!(encoded_output_sigma[1], w * &k2);
        assert_eq!(encoded_output_sigma[2], w_squared * &k2);
        assert_eq!(encoded_output_sigma[3], w_cubed * &k2);

        let w_l = vec![
            Fr::from(2 as u8),
            Fr::from(2 as u8),
            Fr::from(2 as u8),
            Fr::from(2 as u8),
        ];
        let w_r = vec![Fr::from(2 as u8), Fr::one(), Fr::one(), Fr::one()];
        let w_o = vec![Fr::one(), Fr::one(), Fr::one(), Fr::one()];

        test_correct_permutation_poly(
            num_wire_mappings,
            perm,
            &domain,
            w_l.clone(),
            w_r.clone(),
            w_o.clone(),
        );
    }
    #[test]
    fn test_permutation_compute_sigmas() {
        let mut perm: Permutation<E> = Permutation::new();

        let var_one = perm.new_variable(Fr::one());
        let var_two = perm.new_variable(Fr::one() + &Fr::one());
        let var_three = perm.new_variable(Fr::one() + &Fr::one() + &Fr::one());

        let num_wire_mappings = 4;

        // Add four wire mappings
        perm.add_variable_to_map(var_one, var_one, var_two, 0);
        perm.add_variable_to_map(var_two, var_one, var_two, 1);
        perm.add_variable_to_map(var_three, var_three, var_one, 2);
        perm.add_variable_to_map(var_two, var_one, var_three, 3);

        /*
        Below is a sketch of the map created by adding the specific variables into the map

        var_one : {L0,R0, R1, O2, R3 }
        var_two : {O0, L1, O1, L3}
        var_three : {L2, R2, O3}

        Left_Sigma : {0,1,2,3} -> {R0,O1,R2,O0}
        Right_Sigma : {0,1,2,3} -> {R1, O2, O3, L0}
        Out_Sigma : {0,1,2,3} -> {L1, L3, R3, L2}

        */

        let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
        let left_sigma = &sigmas[0];
        let right_sigma = &sigmas[1];
        let out_sigma = &sigmas[2];

        // Check the left sigma polynomial
        assert_eq!(left_sigma[0] - (WireType::Right as usize), 0);
        assert_eq!(left_sigma[1] - (WireType::Output as usize), 1);
        assert_eq!(left_sigma[2] - (WireType::Right as usize), 2);
        assert_eq!(left_sigma[3] - (WireType::Output as usize), 0);

        // Check the right sigma polynomial
        assert_eq!(right_sigma[0] - (WireType::Right as usize), 1);
        assert_eq!(right_sigma[1] - (WireType::Output as usize), 2);
        assert_eq!(right_sigma[2] - (WireType::Output as usize), 3);
        assert_eq!(right_sigma[3] - (WireType::Left as usize), 0);

        // Check the output sigma polynomial
        assert_eq!(out_sigma[0] - (WireType::Left as usize), 1);
        assert_eq!(out_sigma[1] - (WireType::Left as usize), 3);
        assert_eq!(out_sigma[2] - (WireType::Right as usize), 3);
        assert_eq!(out_sigma[3] - (WireType::Left as usize), 2);

        /*

        Check that the unique encodings of the sigma polynomials have been computed properly
        Left_Sigma : {R0,O1,R2,O0}
            When encoded using w, k1,k2 we have {1 * k1, w * k2, w^2 *k1, w^3 * k2}

        Right_Sigma : {R1, O2, O3, L0}
            When encoded using w, k1,k2 we have {1 * k1, w * k2, w^2 * k2, w^3}

        Out_Sigma : {L1, L3, R3, L2}
            When encoded using w, k1, k2 we have {1, w , w^2 * k1, w^3}
        */
        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let k1 = Fr::multiplicative_generator();
        let k2 = Fr::from(13u8);
        let w: Fr = domain.group_gen;
        let w_squared = w.pow(&[2 as u64]);
        let w_cubed = w.pow(&[3 as u64]);
        // check the left sigmas have been encoded properly
        let encoded_left_sigma = perm.compute_permutation_lagrange(left_sigma, &domain);
        assert_eq!(encoded_left_sigma[0], k1);
        assert_eq!(encoded_left_sigma[1], w * &k2);
        assert_eq!(encoded_left_sigma[2], w_squared * &k1);
        assert_eq!(encoded_left_sigma[3], Fr::one() * &k2);

        // check the right sigmas have been encoded properly
        let encoded_right_sigma = perm.compute_permutation_lagrange(right_sigma, &domain);
        assert_eq!(encoded_right_sigma[0], w * &k1);
        assert_eq!(encoded_right_sigma[1], w_squared * &k2);
        assert_eq!(encoded_right_sigma[2], w_cubed * &k2);
        assert_eq!(encoded_right_sigma[3], Fr::one());

        // check the output sigmas have been encoded properly
        let encoded_output_sigma = perm.compute_permutation_lagrange(out_sigma, &domain);
        assert_eq!(encoded_output_sigma[0], w);
        assert_eq!(encoded_output_sigma[1], w_cubed);
        assert_eq!(encoded_output_sigma[2], w_cubed * &k1);
        assert_eq!(encoded_output_sigma[3], w_squared);
    }

    #[test]
    // Checks that when gamma = zero and beta = 1
    // root^3 * k_1 * k_2 / (left_sigma * right_sigma * out_sigma) == 1
    // If the encoding for the permutation does not have unique values then this test would fail
    fn test_permutation_encoding_has_unique_values() {
        let mut perm: Permutation<E> = Permutation::new();
        let k1 = Fr::multiplicative_generator();
        let k2 = Fr::from(13u8);

        let num_wire_mappings = 4;

        let var_one = perm.new_variable(Fr::one());
        let var_two = perm.new_variable(Fr::one() + &Fr::one());
        let var_three = perm.new_variable(Fr::one() + &Fr::one() + &Fr::one());

        // Add four wire mappings
        perm.add_variable_to_map(var_one, var_one, var_two, 0);
        perm.add_variable_to_map(var_two, var_one, var_two, 1);
        perm.add_variable_to_map(var_three, var_three, var_one, 2);
        perm.add_variable_to_map(var_two, var_one, var_three, 3);

        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();

        let _ = perm.compute_sigma_polynomials(num_wire_mappings, &domain);

        let mut prod_left_sigma = Fr::one();
        for element in perm.left_sigma_mapping.unwrap().iter() {
            prod_left_sigma = prod_left_sigma * &element;
        }
        let mut prod_right_sigma = Fr::one();
        for element in perm.right_sigma_mapping.unwrap().iter() {
            prod_right_sigma = prod_right_sigma * &element;
        }
        let mut prod_out_sigma = Fr::one();
        for element in perm.out_sigma_mapping.unwrap().iter() {
            prod_out_sigma = prod_out_sigma * &element;
        }

        let copy_grand_prod = (prod_left_sigma * &prod_right_sigma) * &prod_out_sigma;

        let mut identity_grand_prod = Fr::one();
        for element in domain.elements() {
            let root_cubed = element.pow(&[3 as u64]);
            let prod = (root_cubed * &k1) * &k2;
            identity_grand_prod = identity_grand_prod * &prod;
        }

        assert_eq!(identity_grand_prod / &copy_grand_prod, Fr::one());
    }

    #[test]
    fn test_basic_slow_permutation_poly() {
        let num_wire_mappings = 2;
        let mut perm: Permutation<E> = Permutation::new();
        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();

        let var_one = perm.new_variable(Fr::one());
        let var_two = perm.new_variable(Fr::one() + &Fr::one());
        let var_three = perm.new_variable(Fr::one() + &Fr::one() + &Fr::one());

        perm.add_variable_to_map(var_one, var_two, var_three, 0);
        perm.add_variable_to_map(var_three, var_two, var_one, 1);

        let w_l: Vec<_> = vec![Fr::one(), Fr::from(3 as u8)];
        let w_r: Vec<_> = vec![Fr::from(2 as u8), Fr::from(2 as u8)];
        let w_o: Vec<_> = vec![Fr::from(3 as u8), Fr::one()];

        test_correct_permutation_poly(
            num_wire_mappings,
            perm,
            &domain,
            w_l.clone(),
            w_r.clone(),
            w_o.clone(),
        );
    }

    // shifts the polynomials by one root of unity
    fn shift_poly_by_one(z_coefficients: Vec<Fr>) -> Vec<Fr> {
        let mut shifted_z_coefficients = z_coefficients;
        shifted_z_coefficients.push(shifted_z_coefficients[0]);
        shifted_z_coefficients.remove(0);
        shifted_z_coefficients
    }

    fn test_correct_permutation_poly(
        n: usize,
        mut perm: Permutation<E>,
        domain: &EvaluationDomain<Fr>,
        w_l: Vec<Fr>,
        w_r: Vec<Fr>,
        w_o: Vec<Fr>,
    ) {
        // 0. Generate beta and gammma challenges
        //
        let beta = Fr::rand(&mut rand::thread_rng());
        let gamma = Fr::rand(&mut rand::thread_rng());
        assert_ne!(gamma, beta); // This will make the z(gW) =

        //1. Compute the permutation polynomial using both methods
        // XXX: We should run benchmarks for these two methods
        //
        perm.compute_sigma_polynomials(n, &domain);
        let (z_vec, numerator_components, denominator_components) = perm
            .compute_slow_permutation_poly(
                domain,
                w_l.clone().into_iter(),
                w_r.clone().into_iter(),
                w_o.clone().into_iter(),
                &beta,
                &gamma,
            );

        let fast_z_vec =
            perm.compute_fast_permutation_poly(domain, &w_l, &w_r, &w_o, &beta, &gamma);
        assert_eq!(fast_z_vec, z_vec);

        // 2. First we perform basic tests on the permutation vector
        //
        // Check that the vector has length `n` and that the first element is `1`
        assert_eq!(z_vec.len(), n);
        assert_eq!(&z_vec[0], &Fr::one());
        //
        // Check that the \prod{f_i} / \prod{g_i} = 1
        // Where f_i and g_i are the numerator and denominator components in the permutation polynomial
        let (mut a_0, mut b_0) = (Fr::one(), Fr::one());
        for n in numerator_components.iter() {
            a_0 = a_0 * &n;
        }
        for n in denominator_components.iter() {
            b_0 = b_0 * &n;
        }
        assert_eq!(a_0 / &b_0, Fr::one());

        //3. Now we perform the two checks that need to be done on the permutation polynomial (z)
        let z_poly = Polynomial::from_coefficients_vec(domain.ifft(&z_vec));
        //
        // Check that z(w^{n+1}) == z(1) == 1
        // This is the first check in the protocol
        assert_eq!(z_poly.evaluate(Fr::one()), Fr::one());
        let n_plus_one = domain.elements().last().unwrap() * &domain.group_gen;
        assert_eq!(z_poly.evaluate(n_plus_one), Fr::one());
        //
        // Check that when z is unblinded, it has the correct degree
        assert_eq!(z_poly.degree(), n - 1);
        //
        // Check relationship between z(X) and z(Xw)
        // This is the second check in the protocol
        let roots: Vec<_> = domain.elements().collect();

        for i in 1..roots.len() {
            let current_root = roots[i];
            let next_root = current_root * &domain.group_gen;

            let current_identity_perm_product = &numerator_components[i];
            assert_ne!(current_identity_perm_product, &Fr::zero());

            let current_copy_perm_product = &denominator_components[i];
            assert_ne!(current_copy_perm_product, &Fr::zero());

            assert_ne!(current_copy_perm_product, current_identity_perm_product);

            let z_eval = z_poly.evaluate(current_root);
            assert_ne!(z_eval, Fr::zero());

            let z_eval_shifted = z_poly.evaluate(next_root);
            assert_ne!(z_eval_shifted, Fr::zero());

            // Z(Xw) * copy_perm
            let lhs = z_eval_shifted * &current_copy_perm_product;
            // Z(X) * iden_perm
            let rhs = z_eval * &current_identity_perm_product;
            assert_eq!(
                lhs, rhs,
                "check failed at index: {}\'n lhs is : {:?} \n rhs is :{:?}",
                i, lhs, rhs
            );
        }

        // Test that the shifted polynomial is correct
        let shifted_z = shift_poly_by_one(fast_z_vec);
        let shifted_z_poly = Polynomial::from_coefficients_vec(domain.ifft(&shifted_z));
        for element in domain.elements() {
            let z_eval = z_poly.evaluate(element * &domain.group_gen);
            let shifted_z_eval = shifted_z_poly.evaluate(element);

            assert_eq!(z_eval, shifted_z_eval)
        }
    }
}
