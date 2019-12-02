use algebra::curves::PairingEngine;
use algebra::fields::{Field, PrimeField};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use poly_commit::kzg10::UniversalParams;

use crate::srs;
use crate::transcript::TranscriptProtocol;
use merlin::Transcript;

/// A composer is a circuit builder
/// and will dictate how a cirucit is built
/// We will have a default Composer called `StandardComposer`
pub struct StandardComposer<E: PairingEngine> {
    // n represents the number of arithmetic gates in the circuit
    n: usize,

    // Selector vectors
    //
    // Multiplier selector
    q_m: Vec<E::Fr>,
    // Left wire selector
    q_l: Vec<E::Fr>,
    // Right wire selector
    q_r: Vec<E::Fr>,
    // output wire selector
    q_o: Vec<E::Fr>,
    // constant wire selector
    q_c: Vec<E::Fr>,

    // witness vectors
    w_l: Vec<Variable>,
    w_r: Vec<Variable>,
    w_o: Vec<Variable>,

    // These are the actual variable values
    // N.B. They should not be exposed to the end user once added into the composer
    variables: Vec<E::Fr>,

    // maps variables to the wire data that they are assosciated with
    // To then later create the necessary permutations
    // XXX: the index will be the Variable reference, so it may be better to use a map to be more explicit here
    variable_map: Vec<Vec<WireData>>,

    sigmas: Vec<Vec<usize>>,
}

// Stores the data for a specific wire
// This data is the gate index and the type of wire
struct WireData {
    gate_index: usize,
    wire_type: WireType,
}

impl WireData {
    fn new(index: usize, wire_type: WireType) -> Self {
        WireData {
            gate_index: index,
            wire_type: wire_type,
        }
    }
}

// Encoding for different wire types
#[derive(Copy, Clone)]
enum WireType {
    Left = 0,
    Right = (1 << 30),
    Output = (1 << 31),
}

impl From<&usize> for WireType {
    fn from(n: &usize) -> WireType {
        match ((n >> 30) as usize) & (3 as usize) {
            2 => WireType::Output,
            1 => WireType::Right,
            _ => WireType::Left,
        }
    }
}
/// Represents a variable in a constraint system.
/// The value is a reference to the position of the value in the variables vector
#[derive(Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(usize);

impl<E: PairingEngine> StandardComposer<E> {
    pub fn new() -> Self {
        StandardComposer::with_expected_size(0)
    }

    // Creates a new circuit with an expected circuit size
    // This will allow for less reallocations when building the circuit
    pub fn with_expected_size(expected_size: usize) -> Self {
        StandardComposer {
            n: 0,

            q_m: Vec::with_capacity(expected_size),
            q_l: Vec::with_capacity(expected_size),
            q_r: Vec::with_capacity(expected_size),
            q_o: Vec::with_capacity(expected_size),
            q_c: Vec::with_capacity(expected_size),

            w_l: Vec::with_capacity(expected_size),
            w_r: Vec::with_capacity(expected_size),
            w_o: Vec::with_capacity(expected_size),

            variables: Vec::with_capacity(expected_size),
            variable_map: Vec::new(),

            sigmas: Vec::new(),
        }
    }

    // Pads the circuit to the next power of two
    // diff is the difference between circuit size and next power of two
    fn pad(&mut self, diff: usize) {
        // Add a zero variable to circuit
        let zero_scalar = E::Fr::zero();
        let zero_var = self.add_input(zero_scalar);

        let zeroes_scalar = vec![zero_scalar; diff];
        let zeroes_var = vec![zero_var; diff];

        self.q_m.extend(zeroes_scalar.iter());
        self.q_l.extend(zeroes_scalar.iter());
        self.q_r.extend(zeroes_scalar.iter());
        self.q_o.extend(zeroes_scalar.iter());
        self.q_c.extend(zeroes_scalar.iter());

        self.w_l.extend(zeroes_var.iter());
        self.w_r.extend(zeroes_var.iter());
        self.w_o.extend(zeroes_var.iter());

        self.n = self.n + diff;
    }

    // Computes the pre-processed polynomials
    // So the verifier can verify a proof made using this circuit
    pub fn preprocess(
        &mut self,
        public_parameters: &UniversalParams<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        domain: &EvaluationDomain<E::Fr>,
    ) {
        let k = self.q_m.len();
        assert!(self.q_o.len() == k);
        assert!(self.q_l.len() == k);
        assert!(self.q_r.len() == k);
        assert!(self.q_c.len() == k);
        assert!(self.w_l.len() == k);
        assert!(self.w_r.len() == k);
        assert!(self.w_o.len() == k);

        //0. Pad circuit
        self.pad(domain.size as usize - self.n);

        // 2. Circuit polynomials
        //
        // IFFT to get lagrange polynomials on witness instances
        let q_m_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_m));
        let q_l_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_l));
        let q_r_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_r));
        let q_o_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_o));
        let q_c_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_c));

        // Commit to circuit polynomials
        //
        let (ck, vk) = srs::trim(public_parameters, self.n).unwrap();
        let q_m_poly_commit = srs::commit(&ck, &q_m_poly);
        let q_l_poly_commit = srs::commit(&ck, &q_l_poly);
        let q_r_poly_commit = srs::commit(&ck, &q_r_poly);
        let q_o_poly_commit = srs::commit(&ck, &q_o_poly);
        let q_c_poly_commit = srs::commit(&ck, &q_c_poly);

        // Add selector polynomials to transcript
        transcript.append_commitments(
            vec![b"q_m", b"q_l", b"q_r", b"q_o", b"q_c"],
            vec![
                &q_m_poly_commit,
                &q_l_poly_commit,
                &q_r_poly_commit,
                &q_o_poly_commit,
                &q_c_poly_commit,
            ],
        );

        // FIRST SNARK OUPUT COMPLETE
        // --------- //

        // Now compute the permutation polynomials
        let (left_sigma_poly, right_sigma_poly, out_sigma_poly) =
            self.compute_sigma_polynomials(domain);
    }

    fn compute_sigma_polynomials(
        &mut self,
        domain: &EvaluationDomain<E::Fr>,
    ) -> (Polynomial<E::Fr>, Polynomial<E::Fr>, Polynomial<E::Fr>) {
        // Compute sigma mappings
        self.compute_sigma_permutations();

        // convert the permutation mappings to actual functions
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

    // Prove will compute the pre-processed polynomials and
    // produce a proof
    pub fn prove(
        &mut self,
        public_parameters: &UniversalParams<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
    ) {
        let domain = EvaluationDomain::new(self.n).unwrap();

        // Pre-process circuit
        self.preprocess(public_parameters, transcript, &domain);

        //1. Witness Polynomials
        //
        // Convert Variables to Scalars
        let w_l_scalar: Vec<_> = self.w_l.iter().map(|var| self.variables[var.0]).collect();
        let w_r_scalar: Vec<_> = self.w_r.iter().map(|var| self.variables[var.0]).collect();
        let w_o_scalar: Vec<_> = self.w_o.iter().map(|var| self.variables[var.0]).collect();

        // IFFT to get lagrange polynomials on witnesses
        let mut w_l_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_l_scalar));
        let mut w_r_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_r_scalar));
        let mut w_o_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_o_scalar));

        // Add blinding values to polynomial
        let b_1 = transcript.challenge_scalar(b"b_1");
        let b_2 = transcript.challenge_scalar(b"b_2");
        let b_3 = transcript.challenge_scalar(b"b_3");
        let b_4 = transcript.challenge_scalar(b"b_4");
        let b_5 = transcript.challenge_scalar(b"b_5");
        let b_6 = transcript.challenge_scalar(b"b_6");

        let w_l_blinder =
            Polynomial::from_coefficients_slice(&[b_1, b_2]).mul_by_vanishing_poly(domain);
        let w_r_blinder =
            Polynomial::from_coefficients_slice(&[b_4, b_3]).mul_by_vanishing_poly(domain);
        let w_o_blinder =
            Polynomial::from_coefficients_slice(&[b_6, b_5]).mul_by_vanishing_poly(domain);

        // blind with zero polynomials
        w_l_poly = &w_l_poly + &w_l_blinder;
        w_r_poly = &w_r_poly + &w_r_blinder;
        w_o_poly = &w_o_poly + &w_o_blinder;

        // Commit to witness polynomials
        let (ck, vk) = srs::trim(public_parameters, self.n).unwrap();
        let w_l_poly_commit = srs::commit(&ck, &w_l_poly);
        let w_r_poly_commit = srs::commit(&ck, &w_r_poly);
        let w_o_poly_commit = srs::commit(&ck, &w_o_poly);
    }

    // Adds a value to the circuit and returns its
    // index reference
    fn add_input(&mut self, s: E::Fr) -> Variable {
        self.variables.push(s);

        self.variable_map.push(Vec::new());

        Variable(self.variables.len() - 1)
    }
    // Circuit size is the amount of gates in the circuit
    fn circuit_size(&self) -> usize {
        self.n
    }

    fn add_variable_to_map(&mut self, a: Variable, b: Variable, c: Variable) {
        let num_variables = self.variable_map.len();
        assert!(num_variables > a.0);
        assert!(num_variables > b.0);
        assert!(num_variables > c.0);

        let left: WireData = WireData::new(self.n, WireType::Left);
        let right: WireData = WireData::new(self.n, WireType::Right);
        let output: WireData = WireData::new(self.n, WireType::Output);

        // Map each variable to the wires it is assosciated with
        self.variable_map[a.0].push(left);
        self.variable_map[b.0].push(right);
        self.variable_map[c.0].push(output);
    }

    // Adds an add gate to the circuit
    // This API is not great for the average user, what we can do is make separate functions for r1cs format
    pub fn add_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_l: E::Fr,
        q_r: E::Fr,
        q_o: E::Fr,
        q_c: E::Fr,
    ) {
        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);

        // For an add gate, q_m is zero
        self.q_m.push(E::Fr::zero());

        // Add selector vectors
        self.q_l.push(q_l);
        self.q_r.push(q_r);
        self.q_o.push(q_o);
        self.q_c.push(q_c);

        self.add_variable_to_map(a, b, c);

        self.n = self.n + 1;
    }

    pub fn mul_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_m: E::Fr,
        q_o: E::Fr,
        q_c: E::Fr,
    ) {
        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);

        // For a mul gate q_L and q_R is zero
        self.q_l.push(E::Fr::zero());
        self.q_r.push(E::Fr::zero());

        // Add selector vectors
        self.q_m.push(q_m);
        self.q_o.push(q_o);
        self.q_c.push(q_c);

        self.add_variable_to_map(a, b, c);

        self.n = self.n + 1;
    }

    pub fn add_bool_gate(&mut self, a: Variable) {
        self.w_l.push(a);
        self.w_r.push(a);
        self.w_o.push(a);

        self.q_m.push(E::Fr::one());
        self.q_l.push(E::Fr::zero());
        self.q_r.push(E::Fr::zero());
        self.q_o.push(-E::Fr::one());
        self.q_c.push(E::Fr::zero());

        self.add_variable_to_map(a, a, a);

        self.n = self.n + 1;
    }

    // Computes sigma_1, sigma_2 and sigma_3 permutations
    fn compute_sigma_permutations(&mut self) {
        let sigma_1: Vec<_> =
            (0 + WireType::Left as usize..self.n + WireType::Left as usize).collect();
        let sigma_2: Vec<_> =
            (0 + WireType::Right as usize..self.n + WireType::Right as usize).collect();
        let sigma_3: Vec<_> =
            (0 + WireType::Output as usize..self.n + WireType::Output as usize).collect();

        assert_eq!(sigma_1.len(), self.n);
        assert_eq!(sigma_2.len(), self.n);
        assert_eq!(sigma_3.len(), self.n);

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

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381;
    use algebra::fields::bls12_381::Fr;
    // Ensures a + b - c = 0
    fn simple_add_gadget<E: PairingEngine>(
        composer: &mut StandardComposer<E>,
        a: Variable,
        b: Variable,
        c: Variable,
    ) {
        let q_l = E::Fr::one();
        let q_r = E::Fr::one();
        let q_o = -E::Fr::one();
        let q_c = E::Fr::zero();

        composer.add_gate(a, b, c, q_l, q_r, q_o, q_c);
    }

    // Returns a composer with `n` constraints
    fn add_dummy_composer<E: PairingEngine>(n: usize) -> StandardComposer<E> {
        let mut composer = StandardComposer::new();

        let one = E::Fr::one();
        let two = E::Fr::one() + &E::Fr::one();

        let var_one = composer.add_input(one);
        let var_two = composer.add_input(two);

        for _ in 0..n {
            simple_add_gadget(&mut composer, var_one, var_one, var_two);
        }

        // Add a dummy constraint so that we do not have zero polynomials
        composer.q_m.push(E::Fr::from(1));
        composer.q_l.push(E::Fr::from(2));
        composer.q_r.push(E::Fr::from(3));
        composer.q_o.push(E::Fr::from(4));
        composer.q_c.push(E::Fr::from(5));

        let var_six = composer.add_input(E::Fr::from(6.into()));
        let var_seven = composer.add_input(E::Fr::from(7.into()));
        let var_min_twenty = composer.add_input(-E::Fr::from(20.into()));

        composer.w_l.push(var_six);
        composer.w_r.push(var_seven);
        composer.w_o.push(var_min_twenty);

        composer.n = composer.n + 1;

        composer
    }
    #[test]
    fn test_pad() {
        let num_constraints = 100;
        let mut composer: StandardComposer<Bls12_381> = add_dummy_composer(num_constraints);

        // Pad the circuit to next power of two
        let next_pow_2 = composer.n.next_power_of_two() as u64;
        composer.pad(next_pow_2 as usize - composer.n);

        let size = composer.n;
        assert!(size.is_power_of_two());
        assert!(composer.q_m.len() == size);
        assert!(composer.q_l.len() == size);
        assert!(composer.q_o.len() == size);
        assert!(composer.q_r.len() == size);
        assert!(composer.q_c.len() == size);
        assert!(composer.w_l.len() == size);
        assert!(composer.w_r.len() == size);
        assert!(composer.w_o.len() == size);
    }

    #[test]
    fn test_compute_permutation() {
        let mut transcript = Transcript::new(b"plonk");

        let num_constraints = 10;
        let mut composer: StandardComposer<Bls12_381> = add_dummy_composer(num_constraints);

        // Pad the circuit to next power of two
        let next_pow_2 = composer.n.next_power_of_two() as u64;
        composer.pad(next_pow_2 as usize - composer.n);

        // Compute permutation mappings
        composer.compute_sigma_permutations();

        // Check that the permutations are the correct size
        // and that we have the correct amount of permutation functions
        assert_eq!(composer.sigmas.len(), 3);
        assert_eq!(composer.sigmas[0].len(), composer.n);
        assert_eq!(composer.sigmas[1].len(), composer.n);
        assert_eq!(composer.sigmas[2].len(), composer.n);

        let max_degree = 100;
        let public_parameters = srs::setup(max_degree);

        let domain = EvaluationDomain::new(composer.n).unwrap();

        // Pre-process circuit
        let preprocessed_circuit =
            composer.preprocess(&public_parameters, &mut transcript, &domain);
    }

    #[test]
    fn test_circuit_size() {
        let mut composer: StandardComposer<Bls12_381> = StandardComposer::new();

        let one = Fr::one();
        let two = one + &one;

        let var_one = composer.add_input(one);
        let var_two = composer.add_input(two);

        let n = 20;

        for _ in 0..n {
            simple_add_gadget(&mut composer, var_one, var_one, var_two);
        }

        assert_eq!(n, composer.circuit_size())
    }
}
