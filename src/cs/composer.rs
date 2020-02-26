use super::linearisation::Lineariser;
use super::opening::commitmentOpener;
use super::{
    constraint_system::{LinearCombination, Variable},
    permutation::Permutation,
    proof::Proof,
    Composer, PreProcessedCircuit,
};
use crate::{cs::quotient_poly::QuotientToolkit, srs, transcript::TranscriptProtocol};
use algebra::curves::bls12_381::Bls12_381;
use algebra::curves::PairingEngine;
use algebra::fields::bls12_381::Fr;
use algebra::fields::PrimeField;
use ff_fft::EvaluationDomain;
use num_traits::{One, Zero};
use poly_commit::kzg10::{Powers, UniversalParams, VerifierKey};
use rand_core::{CryptoRng, RngCore};
use std::str::FromStr;
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

        // 2a. Convert selector evaluations to selector coefficients
        let q_m_coeffs = domain.ifft(&self.q_m);
        let q_l_coeffs = domain.ifft(&self.q_l);
        let q_r_coeffs = domain.ifft(&self.q_r);
        let q_o_coeffs = domain.ifft(&self.q_o);
        let q_c_coeffs = domain.ifft(&self.q_c);

        // 2b. Compute 4n evaluations of selector polynomial
        let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
        let q_m_eval_4n = domain_4n.fft(&q_m_coeffs);
        let q_l_eval_4n = domain_4n.fft(&q_l_coeffs);
        let q_r_eval_4n = domain_4n.fft(&q_r_coeffs);
        let q_o_eval_4n = domain_4n.fft(&q_o_coeffs);
        let q_c_eval_4n = domain_4n.fft(&q_c_coeffs);

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
                (q_m_coeffs, q_m_poly_commit, q_m_eval_4n),
                (q_l_coeffs, q_l_poly_commit, q_l_eval_4n),
                (q_r_coeffs, q_r_poly_commit, q_r_eval_4n),
                (q_o_coeffs, q_o_poly_commit, q_o_eval_4n),
                (q_c_coeffs, q_c_poly_commit, q_c_eval_4n),
            ],
            left_sigma: (left_sigma_coeffs, left_sigma_poly_commit),
            right_sigma: (right_sigma_coeffs, right_sigma_poly_commit),
            out_sigma: (out_sigma_coeffs, out_sigma_poly_commit),
        }
    }

    // Ready will setup the srs in the case of the prover and
    // regenerate the keys in the case of the verifier returning
    // the EvalDomain, UniversalParams, VerifierKey and Powers
    fn ready<'a, P: PrimeField>(
        &self,
        pub_params: Option<UniversalParams<Bls12_381>>,
    ) -> (
        UniversalParams<Bls12_381>,
        Powers<'a, Bls12_381>,
        VerifierKey<Bls12_381>,
        EvaluationDomain<P>,
    ) {
        let public_params =
            pub_params.unwrap_or_else(|| srs::setup(2 * self.circuit_size().next_power_of_two()));
        let (ck, vk) =
            srs::trim(&public_params, 2 * self.circuit_size().next_power_of_two()).unwrap();
        let domain = EvaluationDomain::new(self.circuit_size()).unwrap();
        (public_params, ck, vk, domain)
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
        println!("w_l_ifft -> {:?}", w_l_coeffs.len());
        let mut w_r_coeffs = domain.ifft(&w_r_scalar);
        println!("w_r_ifft -> {:?}", w_r_coeffs.len());
        let mut w_o_coeffs = domain.ifft(&w_o_scalar);
        println!("w_o_ifft -> {:?}", w_o_coeffs.len());

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
            &z_coeffs,
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
        let Lineariser = Lineariser::new();
        let (lin_coeffs, evaluations) = Lineariser.evaluate_linearisation_polynomial(
            &domain,
            &preprocessed_circuit,
            &(alpha, beta, gamma, z_challenge),
            &w_l_coeffs,
            &w_r_coeffs,
            &w_o_coeffs,
            &t_coeffs,
            &z_coeffs,
        );

        let left_sigma_eval = evaluations.left_sigma_eval;
        let right_sigma_eval = evaluations.right_sigma_eval;
        let perm_eval = evaluations.perm_eval;

        // 2) Add evaluations to transcript
        // 3) Place commitments into proof
        transcript.append_scalar(b"a_eval", &evaluations.a_eval);
        transcript.append_scalar(b"b_eval", &evaluations.b_eval);
        transcript.append_scalar(b"c_eval", &evaluations.c_eval);
        transcript.append_scalar(b"left_sig_eval", &evaluations.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &evaluations.right_sigma_eval);
        transcript.append_scalar(b"perm_eval", &evaluations.perm_eval);
        transcript.append_scalar(b"t_eval", &evaluations.quot_eval);
        transcript.append_scalar(b"r_eval", &evaluations.lin_poly_eval);
        //
        proof.set_witness_poly_evals(
            &evaluations.a_eval,
            &evaluations.b_eval,
            &evaluations.c_eval,
        );
        proof.set_sigma_poly_evals(&left_sigma_eval, &right_sigma_eval);
        proof.set_shifted_perm_poly_eval(&perm_eval);
        proof.set_linearisation_poly_eval(&evaluations.lin_poly_eval);

        // Compute opening challenge `v`
        let v = transcript.challenge_scalar(b"v");

        // Compute opening polynomial
        let comm_opener: commitmentOpener<E> = commitmentOpener::new();
        let (w_z_coeffs, w_zx_coeffs) = comm_opener.compute_opening_polynomials(
            domain.group_gen,
            domain.size(),
            z_challenge,
            &lin_coeffs,
            evaluations,
            &t_low_coeffs,
            &t_mid_coeffs,
            &t_hi_coeffs,
            &w_l_coeffs,
            &w_r_coeffs,
            &w_o_coeffs,
            preprocessed_circuit.left_sigma_poly(),
            preprocessed_circuit.right_sigma_poly(),
            &z_coeffs,
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

    fn public_inputs(&self) -> &[E::Fr] {
        self.public_inputs.as_slice()
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
    pub fn add_input(&mut self, s: E::Fr) -> Variable {
        self.perm.new_variable(s)
    }

    // Generates a Variable that references a value which is
    // for sure different than the other ones previously generated
    // XXX: This is so ugly, but from::<u64> or from() does not work for u64
    pub fn get_verifier_input(&mut self) -> Variable {
        let new_val = (self.perm.variables.len() as u64 + 1u64).to_string();
        let val_fr = match E::Fr::from_str(&new_val) {
            Ok(val) => val,
            Err(_) => E::Fr::one(),
        };
        self.perm.new_variable(val_fr)
    }

    // evaluates a linear combination
    fn eval(&self, lc: LinearCombination<E::Fr>) -> E::Fr {
        let mut sum = E::Fr::zero();
        for (variable, scalar) in lc.terms.iter() {
            let value = self.perm.variables[variable];
            sum += &(value * scalar);
        }
        sum
    }
    // Evaluates a linear combination and adds it's value to the constraint system
    fn add_lc(&mut self, lc: LinearCombination<E::Fr>) -> Variable {
        let eval = self.eval(lc);
        self.add_input(eval)
    }

    // Adds an add gate to the circuit
    pub fn add_gate(
        &mut self,
        a: LinearCombination<E::Fr>,
        b: LinearCombination<E::Fr>,
        q_l: E::Fr,
        q_r: E::Fr,
        q_o: E::Fr,
        q_c: E::Fr,
        pi: E::Fr,
    ) -> (Variable, Variable, Variable) {
        let a_eval = self.eval(a);
        println!("a: {}", a_eval);
        let l = self.add_input(a_eval);
        let b_eval = self.eval(b);
        println!("b: {}", b_eval);
        let r = self.add_input(b_eval);
        // Compute w_o
        let o_eval = ((a_eval * &q_l) + &(b_eval * &q_r) + &pi + &q_c) * &-q_o;
        println!("{:?}", o_eval);
        let o = self.add_input(o_eval);

        self.w_l.push(l);
        self.w_r.push(r);
        self.w_o.push(o);

        // For an add gate, q_m is zero
        self.q_m.push(E::Fr::zero());

        // Add selector vectors
        self.q_l.push(q_l);
        self.q_r.push(q_r);
        self.q_o.push(q_o);
        self.q_c.push(q_c);

        self.public_inputs.push(pi);

        self.perm.add_variable_to_map(l, r, o, self.n);

        self.n = self.n + 1;

        (l, r, o)
    }

    // XXX: Notice that q_o has to be always negative to satisfy the constraint.
    pub fn mul_gate(
        &mut self,
        a: LinearCombination<E::Fr>,
        b: LinearCombination<E::Fr>,
        q_m: E::Fr,
        q_o: E::Fr,
        q_c: E::Fr,
        pi: E::Fr,
    ) -> (Variable, Variable, Variable) {
        let a_eval = self.eval(a);
        //println!("{}", a_eval);
        let l = self.add_input(a_eval);
        let b_eval = self.eval(b);
        //println!("{}", b_eval);
        let r = self.add_input(b_eval);
        // Compute w_o
        let o_eval = (((a_eval * &b_eval) * &q_m) + &q_c + &pi) * &-q_o;
        //println!("{}", o_eval);
        let o = self.add_input(o_eval);

        self.w_l.push(l);
        self.w_r.push(r);
        self.w_o.push(o);

        // For a mul gate q_L and q_R is zero
        self.q_l.push(E::Fr::zero());
        self.q_r.push(E::Fr::zero());

        // Add selector vectors
        self.q_m.push(q_m);
        self.q_o.push(q_o);
        self.q_c.push(q_c);

        self.public_inputs.push(pi);

        self.perm.add_variable_to_map(l, r, o, self.n);

        self.n = self.n + 1;

        (l, r, o)
    }

    pub fn poly_gate(
        &mut self,
        a: LinearCombination<E::Fr>,
        b: LinearCombination<E::Fr>,
        c: LinearCombination<E::Fr>,
        q_m: E::Fr,
        q_l: E::Fr,
        q_r: E::Fr,
        q_o: E::Fr,
        q_c: E::Fr,
        pi: E::Fr,
    ) -> (Variable, Variable, Variable) {
        //println!("{:?}", a);
        let l = self.add_lc(a);
        let r = self.add_lc(b);
        let o = self.add_lc(c);

        self.w_l.push(l);
        self.w_r.push(r);
        self.w_o.push(o);
        self.q_l.push(q_l);
        self.q_r.push(q_r);

        // Add selector vectors
        self.q_m.push(q_m);
        self.q_o.push(q_o);
        self.q_c.push(q_c);

        self.public_inputs.push(pi);

        self.perm.add_variable_to_map(l, r, o, self.n);

        self.n = self.n + 1;

        (l, r, o)
    }

    pub fn constrain_to_constant(
        &mut self,
        a: LinearCombination<E::Fr>,
        constant: E::Fr,
        pi: E::Fr,
    ) {
        let zero = E::Fr::zero();
        let zero_var = self.add_input(zero);
        let constant_var = self.add_input(constant);
        self.poly_gate(
            a,
            constant_var.into(),
            zero_var.into(),
            zero,
            E::Fr::one(),
            -E::Fr::one(),
            zero,
            zero,
            pi,
        );
    }

    // XXX: Seems not correct!
    pub fn bool_gate(&mut self, a: LinearCombination<E::Fr>) -> Variable {
        let lro = self.add_lc(a);

        self.w_l.push(lro);
        self.w_r.push(lro);
        self.w_o.push(lro);

        self.q_m.push(E::Fr::one());
        self.q_l.push(E::Fr::zero());
        self.q_r.push(E::Fr::zero());
        self.q_o.push(-E::Fr::one());
        self.q_c.push(E::Fr::zero());

        self.public_inputs.push(E::Fr::zero());

        self.perm.add_variable_to_map(lro, lro, lro, self.n);

        self.n = self.n + 1;

        lro
    }

    pub fn add_dummy_constraints(&mut self) {
        // Add a dummy constraint so that we do not have zero polynomials
        self.q_m.push(E::Fr::from(1));
        self.q_l.push(E::Fr::from(2));
        self.q_r.push(E::Fr::from(3));
        self.q_o.push(E::Fr::from(4));
        self.q_c.push(E::Fr::from(5));
        self.public_inputs.push(E::Fr::zero());
        let var_six = self.add_input(E::Fr::from(6.into()));
        let var_seven = self.add_input(E::Fr::from(7.into()));
        let var_min_twenty = self.add_input(-E::Fr::from(20.into()));
        self.w_l.push(var_six);
        self.w_r.push(var_seven);
        self.w_o.push(var_min_twenty);
        self.perm
            .add_variable_to_map(var_six, var_seven, var_min_twenty, self.n);
        self.n = self.n + 1;
        //Add another dummy constraint so that we do not get the identity permutation
        self.q_m.push(E::Fr::from(1));
        self.q_l.push(E::Fr::from(1));
        self.q_r.push(E::Fr::from(1));
        self.q_o.push(E::Fr::from(1));
        self.q_c.push(E::Fr::from(127));
        self.public_inputs.push(E::Fr::zero());
        self.w_l.push(var_min_twenty);
        self.w_r.push(var_six);
        self.w_o.push(var_seven);
        self.perm
            .add_variable_to_map(var_min_twenty, var_six, var_seven, self.n);
        self.n = self.n + 1;
    }

    pub fn add_verif_dummy_constraints(&mut self) {
        // Add a dummy constraint so that we do not have zero polynomials
        self.q_m.push(E::Fr::from(1));
        self.q_l.push(E::Fr::from(2));
        self.q_r.push(E::Fr::from(3));
        self.q_o.push(E::Fr::from(4));
        self.q_c.push(E::Fr::from(5));
        self.public_inputs.push(E::Fr::zero());
        let var_x = self.add_input(E::Fr::from(12.into()));
        let var_y = self.add_input(E::Fr::from(14.into()));
        let var_z = self.add_input(-E::Fr::from(40.into()));
        //let var_x = self.get_verifier_input();
        //let var_y = self.get_verifier_input();
        //let var_z = self.get_verifier_input();
        self.w_l.push(var_x);
        self.w_r.push(var_y);
        self.w_o.push(var_z);
        self.perm.add_variable_to_map(var_x, var_y, var_z, self.n);
        self.n = self.n + 1;
        //Add another dummy constraint so that we do not get the identity permutation
        self.q_m.push(E::Fr::from(1));
        self.q_l.push(E::Fr::from(1));
        self.q_r.push(E::Fr::from(1));
        self.q_o.push(E::Fr::from(1));
        self.q_c.push(E::Fr::from(127));
        self.public_inputs.push(E::Fr::zero());
        self.w_l.push(var_z);
        self.w_r.push(var_x);
        self.w_o.push(var_y);
        self.perm.add_variable_to_map(var_z, var_x, var_y, self.n);
        self.n = self.n + 1;
    }
}

mod tests {
    use super::*;
    use algebra::curves::bls12_381::Bls12_381;
    use algebra::fields::bls12_381::Fr;
    use merlin::Transcript;

    // Ensures a + b - c = 0
    fn simple_add_gadget<E: PairingEngine>(
        composer: &mut StandardComposer<E>,
        a: LinearCombination<E::Fr>,
        b: LinearCombination<E::Fr>,
        pi: E::Fr,
    ) {
        let q_l = E::Fr::one();
        let q_r = E::Fr::one();
        let q_o = -E::Fr::one();
        let q_c = E::Fr::zero();

        composer.add_gate(a.into(), b.into(), q_l, q_r, q_o, q_c, pi);
    }

    // Returns a composer with `n` constraints
    fn add_dummy_composer<E: PairingEngine>(n: usize) -> StandardComposer<E> {
        let mut composer = StandardComposer::new();

        let one = E::Fr::one();

        let var_one = composer.add_input(one);
        let var_two: LinearCombination<E::Fr> =
            LinearCombination::from(var_one) + LinearCombination::from(var_one);

        for _ in 0..n {
            simple_add_gadget(&mut composer, var_one.into(), var_one.into(), E::Fr::zero());
        }
        composer.add_dummy_constraints();

        composer
    }

    fn add_verifier_dummy_composer<E: PairingEngine>(n: usize) -> StandardComposer<E> {
        let mut composer = StandardComposer::new();

        let a = composer.get_verifier_input();

        for _ in 0..n {
            simple_add_gadget(&mut composer, a.into(), a.into(), E::Fr::zero());
        }
        composer.add_verif_dummy_constraints();

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
    fn test_prove_verify() {
        // Provers View
        //
        // Generate the Composer and build the circuit
        let mut composer: StandardComposer<Bls12_381> = add_dummy_composer(100000);
        // setup srs
        let (pub_params, ck, _, domain) = composer.ready(None);
        // setup transcript
        let mut transcript = Transcript::new(b"");
        // Preprocess circuit
        let preprocessed_circuit = composer.preprocess(&ck.clone(), &mut transcript, &domain);
        // Build the proff
        let proof = composer.prove(&ck.clone(), &preprocessed_circuit, &mut transcript);

        // Verifiers view
        //
        // Generate the Composer and build the circuit
        let mut composer: StandardComposer<Bls12_381> = add_dummy_composer(100000);
        let (_, ck, vk, domain) = composer.ready(Some(pub_params));
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
    fn test_prove_verify_add_to_zero() {
        // Provers View
        //
        // Generate the Composer and build the circuit
        let mut composer: StandardComposer<Bls12_381> = StandardComposer::new();
        let input = composer.add_input(Fr::zero());
        let min_input = composer.add_input(-Fr::one());
        composer.add_gate(
            input.into(),
            min_input.into(),
            Fr::one(),
            Fr::one(),
            -Fr::one(),
            Fr::zero(),
            Fr::zero(),
        );
        composer.add_dummy_constraints();
        composer.add_dummy_constraints();
        composer.add_dummy_constraints();
        // setup srs
        let (pub_params, ck, _, domain) = composer.ready(None);
        // setup transcript
        let mut transcript = Transcript::new(b"");
        // Preprocess circuit
        let preprocessed_circuit = composer.preprocess(&ck.clone(), &mut transcript, &domain);
        // Build the proff
        let proof = composer.prove(&ck.clone(), &preprocessed_circuit, &mut transcript);

        // Verifiers view
        //
        // Generate the Composer and build the circuit
        let mut composer: StandardComposer<Bls12_381> = StandardComposer::new();
        let input = composer.add_input(Fr::one() + Fr::one());
        let min_input = composer.add_input(-Fr::one() - Fr::one());
        composer.add_gate(
            input.into(),
            min_input.into(),
            Fr::one(),
            Fr::one(),
            -Fr::one(),
            Fr::zero(),
            Fr::zero(),
        );
        composer.add_verif_dummy_constraints();
        composer.add_verif_dummy_constraints();
        composer.add_verif_dummy_constraints();
        let (_, ck, vk, domain) = composer.ready(Some(pub_params));
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
    fn carlos() {
        let mut composer: StandardComposer<Bls12_381> = StandardComposer::new();
        // XXX: Zero makes this crash while one doesn't
        let one = composer.add_input(Fr::zero());
        composer.bool_gate(one.into());
        composer.add_dummy_constraints();
        composer.add_dummy_constraints();
        composer.add_dummy_constraints();
        // setup srs
        let (pub_params, ck, _, domain) = composer.ready(None);
        // setup transcript
        let mut transcript = Transcript::new(b"");
        // Preprocess circuit
        let preprocessed_circuit_1 = composer.preprocess(&ck.clone(), &mut transcript, &domain);
        // Build the proff
        let proof = composer.prove(&ck.clone(), &preprocessed_circuit_1, &mut transcript);
        // Verifiers view
        //
        // Generate the Composer and build the circuit
        let mut composer: StandardComposer<Bls12_381> = StandardComposer::new();
        let whatever = composer.add_input(Fr::from_str("67").unwrap());
        composer.bool_gate(whatever.into());
        composer.add_dummy_constraints();
        composer.add_dummy_constraints();
        composer.add_dummy_constraints();
        let (_, ck, vk, domain) = composer.ready(Some(pub_params));
        // setup transcript
        let mut transcript = Transcript::new(b"");

        // Preprocess circuit
        let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);

        assert_eq!(preprocessed_circuit_1, preprocessed_circuit);

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
        // Provers View
        //
        let mut composer: StandardComposer<Bls12_381> = StandardComposer::new();

        let one = Fr::one();

        let var_one = composer.add_input(one);

        for _ in 1..=4 {
            simple_add_gadget(&mut composer, var_one.into(), var_one.into(), Fr::one());
        }
        composer.add_dummy_constraints();

        // setup srs
        // XXX: We have 2 *n here because the blinding polynomials add a few extra terms to the degree, so it's more than n, we can adjust this later on to be less conservative
        let public_parameters = srs::setup(20 * composer.n.next_power_of_two());
        let (ck, vk) = srs::trim(&public_parameters, 20 * composer.n.next_power_of_two()).unwrap();
        let domain = EvaluationDomain::new(composer.n).unwrap();

        // Generate the proof
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
        let mut composer: StandardComposer<Bls12_381> = StandardComposer::new();

        let var_one = composer.get_verifier_input();

        for _ in 1..=4 {
            simple_add_gadget(&mut composer, var_one.into(), var_one.into(), Fr::zero());
        }
        composer.add_dummy_constraints();
        // setup transcript
        let mut transcript = Transcript::new(b"");

        // Preprocess circuit
        let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);

        // Verify proof
        let ok = proof.verify(
            &preprocessed_circuit,
            &mut transcript,
            &vk,
            &vec![one, one, one, one],
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
            simple_add_gadget(&mut composer, var_one.into(), var_one.into(), Fr::zero());
        }

        assert_eq!(n, composer.circuit_size())
    }
}
