use super::linearisation::lineariser;
use super::opening::commitmentOpener;
use super::{
    constraint_system::Variable, permutation::Permutation, Composer, PreProcessedCircuit, Proof,
};
use crate::{srs, transcript::TranscriptProtocol};
use algebra::UniformRand;
use algebra::{curves::PairingEngine, fields::Field};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use merlin::Transcript;
use poly_commit::kzg10::UniversalParams;
use rand_core::{CryptoRng, RngCore};
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

    perm: Permutation<E>,
}

impl<E: PairingEngine> Composer<E> for StandardComposer<E> {
    // Computes the pre-processed polynomials
    // So the verifier can verify a proof made using this circuit
    fn preprocess(
        &mut self,
        public_parameters: &UniversalParams<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        domain: &EvaluationDomain<E::Fr>,
    ) -> PreProcessedCircuit<E> {
        let k = self.q_m.len();
        assert!(self.q_o.len() == k);
        assert!(self.q_l.len() == k);
        assert!(self.q_r.len() == k);
        assert!(self.q_c.len() == k);
        assert!(self.w_l.len() == k);
        assert!(self.w_r.len() == k);
        assert!(self.w_o.len() == k);

        //1. Pad circuit to a power of two
        self.pad(domain.size as usize - self.n);

        // 2. Convert selector vectors to selector polynomials
        let q_m_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_m));
        let q_l_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_l));
        let q_r_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_r));
        let q_o_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_o));
        let q_c_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.q_c));

        // 3. Compute the sigma polynomials
        let (left_sigma_poly, right_sigma_poly, out_sigma_poly) =
            self.perm.compute_sigma_polynomials(self.n, domain);

        // 4. Commit to polynomials
        //
        let (ck, vk) = srs::trim(public_parameters, self.n).unwrap();
        //
        let q_m_poly_commit = srs::commit(&ck, &q_m_poly);
        let q_l_poly_commit = srs::commit(&ck, &q_l_poly);
        let q_r_poly_commit = srs::commit(&ck, &q_r_poly);
        let q_o_poly_commit = srs::commit(&ck, &q_o_poly);
        let q_c_poly_commit = srs::commit(&ck, &q_c_poly);

        let left_sigma_poly_commit = srs::commit(
            &ck,
            &Polynomial::from_coefficients_vec(left_sigma_poly.clone()),
        );
        let right_sigma_poly_commit = srs::commit(
            &ck,
            &Polynomial::from_coefficients_vec(right_sigma_poly.clone()),
        );
        let out_sigma_poly_commit = srs::commit(
            &ck,
            &Polynomial::from_coefficients_vec(out_sigma_poly.clone()),
        );

        //5. Add polynomial commitments to transcript
        //
        transcript.append_commitment(b"q_m", &q_m_poly_commit);
        transcript.append_commitment(b"q_l", &q_l_poly_commit);
        transcript.append_commitment(b"q_r", &q_r_poly_commit);
        transcript.append_commitment(b"q_o", &q_o_poly_commit);
        transcript.append_commitment(b"q_c", &q_c_poly_commit);

        transcript.append_commitment(b"left_sigma", &left_sigma_poly_commit);
        transcript.append_commitment(b"right_sigma", &right_sigma_poly_commit);
        transcript.append_commitment(b"out_sigma", &out_sigma_poly_commit);

        PreProcessedCircuit {
            selector_polys: vec![
                (q_m_poly, q_m_poly_commit),
                (q_l_poly, q_l_poly_commit),
                (q_r_poly, q_r_poly_commit),
                (q_o_poly, q_o_poly_commit),
                (q_c_poly, q_c_poly_commit),
            ],
            left_sigma_poly: (left_sigma_poly, left_sigma_poly_commit),
            right_sigma_poly: (right_sigma_poly, right_sigma_poly_commit),
            out_sigma_poly: (out_sigma_poly, out_sigma_poly_commit),
        }
    }

    // Prove will compute the pre-processed polynomials and
    // produce a proof
    fn prove<R: RngCore + CryptoRng>(
        &mut self,
        public_parameters: &UniversalParams<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        mut rng: &mut R,
    ) -> Proof {
        let domain = EvaluationDomain::new(self.n).unwrap();

        // Pre-process circuit
        let preprocessed_circuit = self.preprocess(public_parameters, transcript, &domain);

        //1. Witness Polynomials
        //
        // Convert Variables to Scalars
        let (w_l_scalar, w_r_scalar, w_o_scalar) = self.witness_vars_to_scalars();

        // IFFT to get lagrange polynomials on witnesses
        let mut w_l_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_l_scalar));
        let mut w_r_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_r_scalar));
        let mut w_o_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_o_scalar));

        // Add blinding values to polynomial
        let b_1 = E::Fr::rand(&mut rng);
        let b_2 = E::Fr::rand(&mut rng);
        let b_3 = E::Fr::rand(&mut rng);
        let b_4 = E::Fr::rand(&mut rng);
        let b_5 = E::Fr::rand(&mut rng);
        let b_6 = E::Fr::rand(&mut rng);

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

        // compute permutation polynomial
        let (z_poly, beta, gamma) = self.perm.compute_permutation_poly(
            self.n,
            &domain,
            transcript,
            rng,
            w_l_scalar.into_iter(),
            w_r_scalar.into_iter(),
            w_o_scalar.into_iter(),
            &preprocessed_circuit.left_sigma_poly.0,
            &preprocessed_circuit.right_sigma_poly.0,
            &preprocessed_circuit.out_sigma_poly.0,
        );

        // XXX: The problem is that when we compute the permutation poly, we need the mapping
        // But everywhere else, we need the polynomial made using the lagrange bases
        // This will be one of the bigger refactors
        let left_sigma_poly =
            Polynomial::from_coefficients_slice(&preprocessed_circuit.left_sigma_poly.0);
        let right_sigma_poly =
            Polynomial::from_coefficients_slice(&preprocessed_circuit.right_sigma_poly.0);
        let out_sigma_poly =
            Polynomial::from_coefficients_slice(&preprocessed_circuit.out_sigma_poly.0);

        // Third output being done by Carlos
        //
        let alpha = E::Fr::rand(&mut rng); // Comes from quotient computation
        let quotient_poly = Polynomial::from_coefficients_vec(vec![E::Fr::one()]);
        let t_lo = Polynomial::from_coefficients_vec(vec![E::Fr::one()]);
        let t_mid = Polynomial::from_coefficients_vec(vec![E::Fr::one()]);
        let t_hi = Polynomial::from_coefficients_vec(vec![E::Fr::one()]);
        //
        // Fourth output
        let lineariser = lineariser::new();
        let (lin_poly, evaluations, z_challenge) = lineariser.evaluate_linearisation_polynomial(
            transcript,
            &domain,
            &preprocessed_circuit,
            alpha,
            beta,
            gamma,
            &w_l_poly,
            &w_r_poly,
            &w_o_poly,
            &quotient_poly,
            &z_poly,
        );

        // Fifth output
        let comm_opener = commitmentOpener::new();
        let (W_z, W_zx) = comm_opener.compute_opening_polynomials(
            transcript,
            domain.group_gen,
            domain.size(),
            z_challenge,
            &lin_poly,
            &evaluations,
            &t_lo,
            &t_mid,
            &t_hi,
            &w_l_poly,
            &w_r_poly,
            &w_o_poly,
            &left_sigma_poly,
            &right_sigma_poly,
            &z_poly,
        );

        let comm_w_z = srs::commit(&ck, &W_z);
        let comm_w_z_x = srs::commit(&ck, &W_zx);

        Proof {}
    }

    fn circuit_size(&self) -> usize {
        self.n
    }
}

impl<E: PairingEngine> StandardComposer<E> {
    pub fn new() -> Self {
        StandardComposer::with_expected_size(0)
    }

    fn witness_vars_to_scalars(&self) -> (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>) {
        let w_l_scalar: Vec<_> = self.w_l.iter().map(|var| self.variables[var.0]).collect();
        let w_r_scalar: Vec<_> = self.w_r.iter().map(|var| self.variables[var.0]).collect();
        let w_o_scalar: Vec<_> = self.w_o.iter().map(|var| self.variables[var.0]).collect();

        (w_l_scalar, w_r_scalar, w_o_scalar)
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

            perm: Permutation::new(),
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

    // Adds a value to the circuit and returns its
    // index reference
    fn add_input(&mut self, s: E::Fr) -> Variable {
        self.variables.push(s);

        self.perm.variable_map.push(Vec::new());

        Variable(self.variables.len() - 1)
    }

    // Adds an add gate to the circuit
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

        self.perm.add_variable_to_map(a, b, c, self.n);

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

        self.perm.add_variable_to_map(a, b, c, self.n);

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

        self.perm.add_variable_to_map(a, a, a, self.n);

        self.n = self.n + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381;
    use algebra::fields::bls12_381::Fr;

    use rand::thread_rng;

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

    //XXX: Move this test into permutation module and make `compute_sigma_permutation` private
    #[test]
    fn test_compute_permutation() {
        let num_constraints = 70;
        let mut composer: StandardComposer<Bls12_381> = add_dummy_composer(num_constraints);

        // Setup srs
        let max_degree = num_constraints.next_power_of_two() + 1;
        let public_parameters = srs::setup(max_degree);

        // Pad the circuit to next power of two
        let next_pow_2 = composer.n.next_power_of_two() as u64;
        composer.pad(next_pow_2 as usize - composer.n);

        // Compute permutation mappings
        composer.perm.compute_sigma_permutations(composer.n);

        // Check that the permutations are the correct size
        // and that we have the correct amount of permutation functions
        assert_eq!(composer.perm.sigmas.len(), 3);
        assert_eq!(composer.perm.sigmas[0].len(), composer.n);
        assert_eq!(composer.perm.sigmas[1].len(), composer.n);
        assert_eq!(composer.perm.sigmas[2].len(), composer.n);

        let domain = EvaluationDomain::new(composer.n).unwrap();

        // Create transcript
        let mut transcript = Transcript::new(b"plonk");

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
