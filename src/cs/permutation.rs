use super::constraint_system::{Variable, WireData, WireType};
use crate::cs::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::{
    curves::PairingEngine,
    fields::{Field, PrimeField},
};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use poly_commit::kzg10::Commitment;
use itertools::izip;
use rand_core::{CryptoRng, RngCore};
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

        // Map each variable to the wires it is assosciated with
        // This essentially tells use that:
        // Variable `a` is being used in the n'th gate as a left wire
        // Variable `b` is being used in the n'th gate as a right wire
        // Variable `c` is being used in the n'th gate as a output wire
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
            w_l.iter().map(|var| self.variables[var.0]).collect(),
            w_r.iter().map(|var| self.variables[var.0]).collect(),
            w_o.iter().map(|var| self.variables[var.0]).collect(),
        )
    }

    // Computes sigma_1, sigma_2 and sigma_3 permutations from the variable maps
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

    pub fn compute_sigma_polynomials(
        &mut self,
        n: usize,
        domain: &EvaluationDomain<E::Fr>,
    ) -> (Polynomial<E::Fr>, Polynomial<E::Fr>, Polynomial<E::Fr>) {
        // Compute sigma mappings
        let sigmas = self.compute_sigma_permutations(n);

        assert_eq!(sigmas[0].len(), n);
        assert_eq!(sigmas[1].len(), n);
        assert_eq!(sigmas[2].len(), n);

        // define the sigma permutations using two non quadratic residues
        let left_sigma = self.compute_permutation_lagrange(&sigmas[0], domain);
        let right_sigma = self.compute_permutation_lagrange(&sigmas[1], domain);
        let out_sigma = self.compute_permutation_lagrange(&sigmas[2], domain);

        let left_sigma_poly = Polynomial::from_coefficients_vec(domain.ifft(&left_sigma));
        let right_sigma_poly = Polynomial::from_coefficients_vec(domain.ifft(&right_sigma));
        let out_sigma_poly = Polynomial::from_coefficients_vec(domain.ifft(&out_sigma));

        self.left_sigma_mapping = Some(left_sigma);
        self.right_sigma_mapping = Some(right_sigma);
        self.out_sigma_mapping = Some(out_sigma);

        (left_sigma_poly, right_sigma_poly, out_sigma_poly)
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
    ) -> (Polynomial<E::Fr>, E::Fr, E::Fr)
    where
        I: Iterator<Item = E::Fr>,
        R: RngCore + CryptoRng,
    {
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from_repr_raw(13.into());

        let left_sigma_mapping = self.left_sigma_mapping.as_ref().unwrap();
        let right_sigma_mapping = self.right_sigma_mapping.as_ref().unwrap();
        let out_sigma_mapping = self.out_sigma_mapping.as_ref().unwrap();

        // Compute challenges
        let beta = transcript.challenge_scalar(b"beta");
        let gamma = transcript.challenge_scalar(b"gamma");

        // Compute beta * sigma polynomials
        let beta_left_sigma = left_sigma_mapping.iter().map(|sigma| *sigma * &beta);
        let beta_right_sigma = right_sigma_mapping.iter().map(|sigma| *sigma * &beta);
        let beta_out_sigma = out_sigma_mapping.iter().map(|sigma| *sigma * &beta);

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

        // Compute blinding polynomial
        let z_blinder = Polynomial::rand(2, &mut rng).mul_by_vanishing_poly(*domain);

        let z_poly_blinded = &z_poly + &z_blinder;

        (z_poly_blinded, beta, gamma)
    }
    
    #[allow(dead_code)]
    pub fn compute_quotient_poly (
        &self,
        n: usize,
        domain: &EvaluationDomain<E::Fr>,
        transcript: &mut dyn TranscriptProtocol<E>,
        prep_circ: &PreProcessedCircuit<E>,
        w_poly: [&Polynomial<E::Fr>; 3],
        pi_poly: &Polynomial<E::Fr>,
        beta: &E::Fr,
        gamma: &E::Fr,
        z_poly: &Polynomial<E::Fr>,
    ) -> (Polynomial<E::Fr>, Polynomial<E::Fr>, Polynomial<E::Fr>, E::Fr) {

        // Compute `Alpha` randomness
        let alpha = transcript.challenge_scalar(b"alpha");
        // Compute `alpha` polynomial (degree zero).
        let alpha_poly = Polynomial::from_coefficients_slice(&[alpha]);
        // Compute `gamma` polynomial (degree zero). 
        let gamma_poly = Polynomial::from_coefficients_slice(&[*gamma]);

        // Get wire polynomials by its names to clarify the rest of the code.
        let w_l_poly = w_poly[0];
        let w_r_poly = w_poly[1];
        let w_o_poly = w_poly[2];
        // Rename wire-selector polynomials to clarify code. 
        let qm_ws_poly = &prep_circ.selector_polys[0].0;
        let ql_ws_poly = &prep_circ.selector_polys[1].0;
        let qr_ws_poly = &prep_circ.selector_polys[2].0;
        let qo_ws_poly = &prep_circ.selector_polys[3].0;
        let qc_ws_poly = &prep_circ.selector_polys[4].0;

        // t0 represents the first polynomial that forms `t(X)`. 
        let t0 = {
            let t00 = &(w_l_poly * w_r_poly) * qm_ws_poly;
            let t01 = w_l_poly * ql_ws_poly; 
            let t02 = w_r_poly * qr_ws_poly; 
            let t03 = w_o_poly * qo_ws_poly; 
            let t04 = pi_poly + qc_ws_poly;
            // Compute `alpha/Zh(X)`
            let (t05, _) = alpha_poly.divide_by_vanishing_poly(*domain).unwrap();

            &(&(&(&(&t00 + &t01) + &t02) + &t03) + &t04) * &t05
        };

        // t1 represents the second polynomial that forms `t(X)`.
        let t1 = {
            // beta*X poly
            let beta_x_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), *beta]);
            let t10 = w_l_poly + &(&beta_x_poly + &gamma_poly);
            // Beta*k1
            let beta_k1 : E::Fr = *beta * &E::Fr::multiplicative_generator();
            // Beta*k1 poly
            let beta_k1_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), beta_k1]);
            let t11 = &(w_r_poly + &beta_k1_poly) + &gamma_poly;
            // Beta*k2
            let beta_k2 : E::Fr = *beta * &E::Fr::from(13);
            // Beta*k2 poly
            let beta_k2_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), beta_k2]);
            let t12 = &(w_o_poly + &beta_k2_poly) + &gamma_poly;
            // Compute `alpha^2/Zh(X)`
            let (t14, _) = Polynomial::from_coefficients_slice(&[alpha.square()]).divide_by_vanishing_poly(*domain).unwrap();
            
            &(&(&(&t10 * &t11) * &t12) * &z_poly) * &t14
        };

        // t2 represents the third polynomial that forms `t(X)`. 
        let t2 = {
            // Beta poly (Degree 0). 
            let beta_poly = Polynomial::from_coefficients_slice(&[*beta]);
            // Compute Sigma polys. 
            let sigma_1_beta_poly =
            &Polynomial::from_coefficients_slice(&prep_circ.left_sigma_poly.0) * &beta_poly;
            let sigma_2_beta_poly =
            &Polynomial::from_coefficients_slice(&prep_circ.right_sigma_poly.0) * &beta_poly;
            let sigma_3_beta_poly =
            &Polynomial::from_coefficients_slice(&prep_circ.out_sigma_poly.0) * &beta_poly;

            let t20 = &(w_l_poly + &sigma_1_beta_poly) + &gamma_poly;
            let t21 = &(w_r_poly + &sigma_2_beta_poly) + &gamma_poly;
            let t22 = &(w_o_poly + &sigma_3_beta_poly) + &gamma_poly;
            let t23 = self.transpolate_poly_to_unity_root(n, &z_poly);

            // Compute `alpha^2/Zh(X)`
            let (t24, _) = Polynomial::from_coefficients_slice(&[alpha.square()]).divide_by_vanishing_poly(*domain).unwrap();
            &(&(&(&t20 * &t21) * &t22) * &t23) * &t24
        };

        // t3 represents the fourth polynomial that forms `t(X)`.
        let t3 = {
            // Build `1` poly (degree 0). 
            let one_poly = Polynomial::from_coefficients_slice(&[E::Fr::from(1)]);
            let t30 = z_poly - &one_poly;
            // Compute `alpha^3/Zh(X)`
            let (t31, _) = Polynomial::from_coefficients_slice(&[alpha.square() * &alpha]).divide_by_vanishing_poly(*domain).unwrap();
            // Get L1(x) and compute the result. 
            &(&t30 * &t31) * &self.compute_lagrange_poly_evaluation(n as u8)
        };

        let t_x = &(&(&t0 + &t1) - &t2) + &t3;
        // Split `t(X)`

        // Build 0+ X + X^n + X^2n poly. 
        let x_pow_2n = {
            let mut vec = Vec::new();
            for _ in 0..(n*2) {
                vec.push(E::Fr::zero());
            };
            vec.push(E::Fr::from(1));
            vec
        };
        let x_pow_2n_poly = Polynomial::from_coefficients_slice(&x_pow_2n);
        let x_pow_n_poly = Polynomial::from_coefficients_slice(&x_pow_2n[0..=n]);
        
        let t_x_split = self.split_tx_poly(n, t_x);
        // Build t_low(X)
        let t_lo = t_x_split[0].clone();
        // Build t_mid(X)
        let t_mid = &x_pow_n_poly * &t_x_split[1];
        // Build t_hi(X)
        let t_hi = &x_pow_2n_poly * &t_x_split[2];
        (t_lo, t_mid, t_hi, alpha)
    }

    /// Computes the Lagrange polynomial evaluation `L1(z)`. 
    pub fn compute_lagrange_poly_evaluation(&self, n: u8) -> Polynomial<E::Fr> {
        // One as a polynomial of degree 0. 
        let one_poly = Polynomial::from_coefficients_slice(&[E::Fr::from(1)]);
        // Build z_nth vector to get the poly directly in coef form.
        let mut z_nth = Vec::new();
        for _ in 0..n {
            z_nth.push(E::Fr::zero());
        };
        // Add 1 on the n'th term of the vec. 
        z_nth.push(E::Fr::from(1));
        // Build the poly. 
        let z_nth_poly = Polynomial::from_coefficients_vec(z_nth);
        // `n` as polynomial of degree 0. 
        let n_poly = Polynomial::from_coefficients_slice(&[E::Fr::from(n as u8)]);
        let z_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), E::Fr::from(1)]);

        &(&z_nth_poly - &one_poly) / &(&n_poly * &(&z_poly - &one_poly))
    }

    pub fn transpolate_poly_to_unity_root(&self, n: usize, poly: &Polynomial<E::Fr>) -> Polynomial<E::Fr> {
        let domain_4n = EvaluationDomain::new(4*n).unwrap();
        let mut poly_coef = domain_4n.fft(poly);
        poly_coef.push(poly_coef[0]);
        poly_coef.push(poly_coef[1]);
        poly_coef.push(poly_coef[2]);
        poly_coef.push(poly_coef[3]);
        let mut coefs_rotated: Vec<E::Fr> = Vec::with_capacity(poly_coef.len());
        coefs_rotated.clone_from_slice(&poly_coef[4..]);
        let final_poly = Polynomial::from_coefficients_vec(domain_4n.ifft(&coefs_rotated));
        final_poly
    }

    // Split `t(X)` poly into degree-n polynomials.
    pub fn split_tx_poly(&self, n: usize, t_x: Polynomial<E::Fr>) -> [Polynomial<E::Fr>;3] {
        let mut t_lo = t_x.clone();
        t_lo[2*n+1] = E::Fr::zero();
        t_lo[3*n+1] = E::Fr::zero();
        let mut t_mid = t_x.clone();
        t_mid[3*n+1] = E::Fr::zero();
        t_mid[n+1] = E::Fr::zero();
        let mut t_hi = t_x.clone();
        t_hi[2*n+1] = E::Fr::zero();
        t_hi[n+1] = E::Fr::zero();
        [t_lo, t_mid, t_hi]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381 as E;
    use algebra::fields::bls12_381::Fr;
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
        let k2 = Fr::from_repr_raw(13.into());
        let w : Fr = domain.group_gen;
        let w_squared = w.pow(&[2 as u64]);
        let w_cubed = w.pow(&[3 as u64]);
        
        // check the left sigmas have been encoded properly
        let encoded_left_sigma = perm.compute_permutation_lagrange(left_sigma, &domain);    
        assert_eq!(encoded_left_sigma[0], k1);
        assert_eq!(encoded_left_sigma[1], w * &k2);
        assert_eq!(encoded_left_sigma[2], w_squared * &k1);
        assert_eq!(encoded_left_sigma[3], w_cubed * &k2);
        
        
        // check the right sigmas have been encoded properly
        let encoded_right_sigma = perm.compute_permutation_lagrange(right_sigma, &domain);    
        assert_eq!(encoded_right_sigma[0], k1);
        assert_eq!(encoded_right_sigma[1], w * &k2);
        assert_eq!(encoded_right_sigma[2], w_squared * &k2);
        assert_eq!(encoded_right_sigma[3], w_cubed);

        // check the output sigmas have been encoded properly
        let encoded_output_sigma = perm.compute_permutation_lagrange(out_sigma, &domain);    
        assert_eq!(encoded_output_sigma[0], Fr::one());
        assert_eq!(encoded_output_sigma[1], w);
        assert_eq!(encoded_output_sigma[2], w_squared * &k1);
        assert_eq!(encoded_output_sigma[3], w_cubed);

    }
}

// Possible Attack vectors to test for:
// Do not change the gate index and add a different set of wires
// The max_gate_size limit is actually u64::MAX, can make it u128 max and do a check for it in later iterations
