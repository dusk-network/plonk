use super::linearisation::lineariser;
use super::opening::commitmentOpener;
use super::{
    constraint_system::Variable, permutation::Permutation, proof::Proof, Composer,
    PreProcessedCircuit,
};
use crate::{cs::quotient_poly::QuotientToolkit, srs, transcript::TranscriptProtocol};
use algebra::{curves::PairingEngine, fields::Field};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use poly_commit::kzg10::Powers;
use rand_core::{CryptoRng, RngCore};
/// A composer is a circuit builder
/// and will dictate how a circuit is built
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

    public_inputs: Vec<E::Fr>,

    // witness vectors
    w_l: Vec<Variable>,
    w_r: Vec<Variable>,
    w_o: Vec<Variable>,

    perm: Permutation<E>,
}

impl<E: PairingEngine> Composer<E> for StandardComposer<E> {
    // Computes the pre-processed polynomials
    // So the verifier can verify a proof made using this circuit
    fn preprocess(
        &mut self,
        commit_key: &Powers<E>,
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
        let q_m_coeffs = domain.ifft(&self.q_m);
        let q_l_coeffs = domain.ifft(&self.q_l);
        let q_r_coeffs = domain.ifft(&self.q_r);
        let q_o_coeffs = domain.ifft(&self.q_o);
        let q_c_coeffs = domain.ifft(&self.q_c);

        // 3. Compute the sigma polynomials
        let (left_sigma_coeffs, right_sigma_coeffs, out_sigma_coeffs) =
            self.perm.compute_sigma_polynomials(self.n, domain);

        // 4. Commit to polynomials
        //
        let q_m_poly_commit = srs::commit(commit_key, &q_m_coeffs);
        let q_l_poly_commit = srs::commit(commit_key, &q_l_coeffs);
        let q_r_poly_commit = srs::commit(commit_key, &q_r_coeffs);
        let q_o_poly_commit = srs::commit(commit_key, &q_o_coeffs);
        let q_c_poly_commit = srs::commit(commit_key, &q_c_coeffs);

        let left_sigma_poly_commit = srs::commit(commit_key, &left_sigma_coeffs);
        let right_sigma_poly_commit = srs::commit(commit_key, &right_sigma_coeffs);
        let out_sigma_poly_commit = srs::commit(commit_key, &out_sigma_coeffs);

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

        // Append circuit size to transcript
        transcript.circuit_domain_sep(self.circuit_size() as u64);

        PreProcessedCircuit {
            n: self.n,
            selectors: vec![
                (q_m_coeffs, q_m_poly_commit),
                (q_l_coeffs, q_l_poly_commit),
                (q_r_coeffs, q_r_poly_commit),
                (q_o_coeffs, q_o_poly_commit),
                (q_c_coeffs, q_c_poly_commit),
            ],
            left_sigma: (left_sigma_coeffs, left_sigma_poly_commit),
            right_sigma: (right_sigma_coeffs, right_sigma_poly_commit),
            out_sigma: (out_sigma_coeffs, out_sigma_poly_commit),
        }
    }

    // Prove will compute the pre-processed polynomials and
    // produce a proof
    fn prove(
        &mut self,
        commit_key: &Powers<E>,
        preprocessed_circuit: &PreProcessedCircuit<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
    ) -> Proof<E> {
        let domain = EvaluationDomain::new(self.n).unwrap();

        let mut proof = Proof::empty();

        //1. Witness Polynomials
        //
        // Convert Variables to Scalars
        let (w_l_scalar, w_r_scalar, w_o_scalar) = self
            .perm
            .witness_vars_to_scalars(&self.w_l, &self.w_r, &self.w_o);

        // IFFT to get lagrange polynomials on witnesses
        let mut w_l_coeffs = domain.ifft(&w_l_scalar);
        let mut w_r_coeffs = domain.ifft(&w_r_scalar);
        let mut w_o_coeffs = domain.ifft(&w_o_scalar);

        // 1) Commit to witness polynomials
        // 2) Add them to transcript
        // 3) Place commitments into proof
        let w_l_poly_commit = srs::commit(commit_key, &w_l_coeffs);
        let w_r_poly_commit = srs::commit(commit_key, &w_r_coeffs);
        let w_o_poly_commit = srs::commit(commit_key, &w_o_coeffs);
        //
        transcript.append_commitment(b"w_l", &w_l_poly_commit);
        transcript.append_commitment(b"w_r", &w_r_poly_commit);
        transcript.append_commitment(b"w_o", &w_o_poly_commit);
        //
        proof.set_witness_poly_commitments(&w_l_poly_commit, &w_r_poly_commit, &w_o_poly_commit);

        // Compute Permutation challenges to the transcript `beta` and `gamma`
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");

        // compute Permutation polynomial
        let z_coeffs = self.perm.compute_permutation_poly(
            &domain,
            &w_l_scalar,
            &w_r_scalar,
            &w_o_scalar,
            &(beta, gamma),
        );
        let z_poly = Polynomial::from_coefficients_slice(&z_coeffs);
        // 1) Commit to permutation polynomial
        // 2) Add them to transcript
        // 3) Place commitments into proof
        let z_poly_commit = srs::commit(commit_key, &z_coeffs);
        //
        transcript.append_commitment(b"z", &z_poly_commit);
        //
        proof.set_perm_poly_commitment(&z_poly_commit);

        // Compute Quotient challenge `alpha`
        let alpha = transcript.challenge_scalar(b"alpha");

        // Compute Public Inputs Polynomial
        let pi_coeffs = domain.ifft(&self.public_inputs);

        // Compute Quotient polynomial.
        let qt_toolkit = QuotientToolkit::new();
        let t_coeffs = qt_toolkit.compute_quotient_poly(
            &domain,
            &preprocessed_circuit,
            &z_poly,
            [&w_l_coeffs, &w_r_coeffs, &w_o_coeffs],
            &pi_coeffs,
            &(alpha, beta, gamma),
        );

        let (t_low_coeffs, t_mid_coeffs, t_hi_coeffs) =
            self.split_tx_poly(domain.size(), &t_coeffs);

        // 1) Commit to quotient polynomials
        // 2) Add them to transcript
        // 3) Place commitments into proof
        let t_low_commit = srs::commit(commit_key, &t_low_coeffs);
        let t_mid_commit = srs::commit(commit_key, &t_mid_coeffs);
        let t_hi_commit = srs::commit(commit_key, &t_hi_coeffs);
        //
        transcript.append_commitment(b"t_lo", &t_low_commit);
        transcript.append_commitment(b"t_mid", &t_mid_commit);
        transcript.append_commitment(b"t_hi", &t_hi_commit);
        //
        proof.set_quotient_poly_commitments(&t_low_commit, &t_mid_commit, &t_hi_commit);

        // Compute evaluation challenge `z`
        let z_challenge = transcript.challenge_scalar(b"z");

        // Compute Linearisation polynomial
        let lineariser = lineariser::new();
        let (lin_poly, evaluations) = lineariser.evaluate_linearisation_polynomial(
            transcript,
            &domain,
            &preprocessed_circuit,
            &(alpha, beta, gamma, z_challenge),
            &Polynomial::from_coefficients_slice(&w_l_coeffs),
            &Polynomial::from_coefficients_slice(&w_r_coeffs),
            &Polynomial::from_coefficients_slice(&w_o_coeffs),
            &Polynomial::from_coefficients_slice(&t_coeffs),
            &z_poly,
        );

        let a_eval = evaluations[0];
        let b_eval = evaluations[1];
        let c_eval = evaluations[2];
        let left_sigma_eval = evaluations[3];
        let right_sigma_eval = evaluations[4];
        let quot_eval = evaluations[5];
        let lin_poly_eval = evaluations[6];
        let z_hat_eval = evaluations[7];

        // 2) Add evaluations to transcript
        // 3) Place commitments into proof
        transcript.append_scalar(b"a_eval", &a_eval);
        transcript.append_scalar(b"b_eval", &b_eval);
        transcript.append_scalar(b"c_eval", &c_eval);
        transcript.append_scalar(b"left_sig_eval", &left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &right_sigma_eval);
        transcript.append_scalar(b"z_hat_eval", &z_hat_eval);
        transcript.append_scalar(b"t_eval", &quot_eval);
        transcript.append_scalar(b"r_eval", &lin_poly_eval);
        //
        proof.set_witness_poly_evals(&a_eval, &b_eval, &c_eval);
        proof.set_sigma_poly_evals(&left_sigma_eval, &right_sigma_eval);
        proof.set_shifted_perm_poly_eval(&z_hat_eval);
        proof.set_linearisation_poly_eval(&lin_poly_eval);

        // Compute opening challenge `v`
        let v = transcript.challenge_scalar(b"v");

        // Compute opening polynomial
        let comm_opener: commitmentOpener<E> = commitmentOpener::new();
        let (w_z_coeffs, w_zx_coeffs) = comm_opener.compute_opening_polynomials(
            domain.group_gen,
            domain.size(),
            z_challenge,
            &lin_poly.coeffs,
            &evaluations,
            &t_low_coeffs,
            &t_mid_coeffs,
            &t_hi_coeffs,
            &w_l_coeffs,
            &w_r_coeffs,
            &w_o_coeffs,
            preprocessed_circuit.left_sigma_poly(),
            preprocessed_circuit.right_sigma_poly(),
            &z_poly,
            &v,
        );

        // 1) Commit to opening polynomials
        // 2) Place commitments into proof
        let w_z_comm = srs::commit(commit_key, &w_z_coeffs);
        let w_z_x_comm = srs::commit(commit_key, &w_zx_coeffs);
        //
        proof.set_opening_poly_commitments(&w_z_comm, &w_z_x_comm);

        proof
    }

    fn circuit_size(&self) -> usize {
        self.n
    }
}

impl<E: PairingEngine> StandardComposer<E> {
    pub fn new() -> Self {
        StandardComposer::with_expected_size(0)
    }

    // Split `t(X)` poly into three degree-n polynomials.
    pub fn split_tx_poly<'a>(
        &self,
        n: usize,
        t_x: &Vec<E::Fr>,
    ) -> (Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>) {
        (
            t_x[0..n].to_vec(),
            t_x[n..2 * n].to_vec(),
            t_x[2 * n..].to_vec(),
        )
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
            public_inputs: Vec::with_capacity(expected_size),

            w_l: Vec::with_capacity(expected_size),
            w_r: Vec::with_capacity(expected_size),
            w_o: Vec::with_capacity(expected_size),

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

    // Adds a Scalar to the circuit and returns its
    // reference in the constraint system
    fn add_input(&mut self, s: E::Fr) -> Variable {
        self.perm.new_variable(s)
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
        pi: E::Fr,
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

        self.public_inputs.push(pi);

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
        pi: E::Fr,
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

        self.public_inputs.push(pi);

        self.perm.add_variable_to_map(a, b, c, self.n);

        self.n = self.n + 1;
    }

    pub fn bool_gate(&mut self, a: Variable) {
        self.w_l.push(a);
        self.w_r.push(a);
        self.w_o.push(a);

        self.q_m.push(E::Fr::one());
        self.q_l.push(E::Fr::zero());
        self.q_r.push(E::Fr::zero());
        self.q_o.push(-E::Fr::one());
        self.q_c.push(E::Fr::zero());

        self.public_inputs.push(E::Fr::zero());

        self.perm.add_variable_to_map(a, a, a, self.n);

        self.n = self.n + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381;
    use algebra::fields::bls12_381::Fr;
    use merlin::Transcript;

    // Ensures a + b - c = 0
    fn simple_add_gadget<E: PairingEngine>(
        composer: &mut StandardComposer<E>,
        a: Variable,
        b: Variable,
        c: Variable,
        pi: E::Fr,
    ) {
        let q_l = E::Fr::one();
        let q_r = E::Fr::one();
        let q_o = -E::Fr::one();
        let q_c = E::Fr::zero();

        composer.add_gate(a, b, c, q_l, q_r, q_o, q_c, pi);
    }

    // Returns a composer with `n` constraints
    fn add_dummy_composer<E: PairingEngine>(n: usize) -> StandardComposer<E> {
        let mut composer = StandardComposer::new();

        let one = E::Fr::one();
        let two = E::Fr::one() + &E::Fr::one();

        let var_one = composer.add_input(one);
        let var_two = composer.add_input(two);

        for _ in 0..n {
            simple_add_gadget(&mut composer, var_one, var_one, var_two, E::Fr::zero());
        }
        add_dummy_constraints(&mut composer);

        composer
    }

    fn add_dummy_constraints<E: PairingEngine>(composer: &mut StandardComposer<E>) {
        // Add a dummy constraint so that we do not have zero polynomials
        composer.q_m.push(E::Fr::from(1));
        composer.q_l.push(E::Fr::from(2));
        composer.q_r.push(E::Fr::from(3));
        composer.q_o.push(E::Fr::from(4));
        composer.q_c.push(E::Fr::from(5));
        composer.public_inputs.push(E::Fr::zero());

        let var_six = composer.add_input(E::Fr::from(6.into()));
        let var_seven = composer.add_input(E::Fr::from(7.into()));
        let var_min_twenty = composer.add_input(-E::Fr::from(20.into()));

        composer.w_l.push(var_six);
        composer.w_r.push(var_seven);
        composer.w_o.push(var_min_twenty);

        composer.n = composer.n + 1;
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
    fn test_prove_verify() {
        // Common View
        //
        let mut composer: StandardComposer<Bls12_381> = add_dummy_composer(7);
        // setup srs
        // XXX: We have 2 *n here because the blinding polynomials add a few extra terms to the degree, so it's more than n, we can adjust this later on to be less conservative
        let public_parameters = srs::setup(2 * composer.n.next_power_of_two());
        let (ck, vk) = srs::trim(&public_parameters, 2 * composer.n.next_power_of_two()).unwrap();
        let domain = EvaluationDomain::new(composer.n).unwrap();
        // Provers View
        //
        let proof = {
            // setup transcript
            let mut transcript = Transcript::new(b"");
            // Preprocess circuit
            let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);

            composer.prove(&ck, &preprocessed_circuit, &mut transcript)
        };

        // Verifiers view
        //

        // setup transcript
        let mut transcript = Transcript::new(b"");

        // Preprocess circuit
        let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);

        // Verify proof
        let ok = proof.verify(
            &preprocessed_circuit,
            &mut transcript,
            &vk,
            &vec![Fr::zero()],
        );
        assert!(ok);
    }

    #[test]
    fn test_pi() {
        // Common View
        //
        let mut composer: StandardComposer<Bls12_381> = StandardComposer::new();

        let one = Fr::one();
        let three = Fr::one() + &Fr::one() + &Fr::one();

        let var_one = composer.add_input(one);
        let var_three = composer.add_input(three);

        simple_add_gadget(&mut composer, var_one, var_one, var_three, Fr::one());
        simple_add_gadget(&mut composer, var_one, var_one, var_three, Fr::one());
        simple_add_gadget(&mut composer, var_one, var_one, var_three, Fr::one());
        simple_add_gadget(&mut composer, var_one, var_one, var_three, Fr::one());
        add_dummy_constraints(&mut composer);

        // setup srs
        // XXX: We have 2 *n here because the blinding polynomials add a few extra terms to the degree, so it's more than n, we can adjust this later on to be less conservative
        let public_parameters = srs::setup(20 * composer.n.next_power_of_two());
        let (ck, vk) = srs::trim(&public_parameters, 20 * composer.n.next_power_of_two()).unwrap();
        let domain = EvaluationDomain::new(composer.n).unwrap();

        // Provers View
        //
        let proof = {
            // setup transcript
            let mut transcript = Transcript::new(b"");
            // Preprocess circuit
            let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);

            composer.prove(&ck, &preprocessed_circuit, &mut transcript)
        };

        // Verifiers view
        //

        // setup transcript
        let mut transcript = Transcript::new(b"");

        // Preprocess circuit
        let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);

        // Verify proof
        let ok = proof.verify(
            &preprocessed_circuit,
            &mut transcript,
            &vk,
            &composer.public_inputs,
        );
        assert!(ok);
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
            simple_add_gadget(&mut composer, var_one, var_one, var_two, Fr::zero());
        }

        assert_eq!(n, composer.circuit_size())
    }
}
