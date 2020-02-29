use super::quotient_poly;
use super::{proof::Proof, Composer, PreProcessedCircuit};
use crate::commitment_scheme::kzg10::ProverKey;
use crate::constraint_system::{LinearCombination, Variable};
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::transcript::TranscriptProtocol;
use crate::{linearisation_poly, opening_poly, permutation::Permutation};
use bls12_381::Scalar;
use rayon::iter::IntoParallelIterator;
/// A composer is a circuit builder
/// and will dictate how a circuit is built
/// We will have a default Composer called `StandardComposer`
pub struct StandardComposer {
    // n represents the number of arithmetic gates in the circuit
    n: usize,

    // Selector vectors
    //
    // Multiplier selector
    q_m: Vec<Scalar>,
    // Left wire selector
    q_l: Vec<Scalar>,
    // Right wire selector
    q_r: Vec<Scalar>,
    // output wire selector
    q_o: Vec<Scalar>,
    // constant wire selector
    q_c: Vec<Scalar>,

    public_inputs: Vec<Scalar>,

    // witness vectors
    w_l: Vec<Variable>,
    w_r: Vec<Variable>,
    w_o: Vec<Variable>,

    pub(crate) perm: Permutation,
}

impl Composer for StandardComposer {
    // Computes the pre-processed polynomials
    // So the verifier can verify a proof made using this circuit
    fn preprocess(
        &mut self,
        commit_key: &ProverKey,
        transcript: &mut dyn TranscriptProtocol,
        domain: &EvaluationDomain,
    ) -> PreProcessedCircuit {
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
        let q_m_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_m));
        let q_l_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_l));
        let q_r_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_r));
        let q_o_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_o));
        let q_c_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_c));

        // 2b. Compute 4n evaluations of selector polynomial
        let domain_4n = EvaluationDomain::new(4 * domain.size()).unwrap();
        let q_m_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_m_poly.coeffs), domain_4n);
        let q_l_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_l_poly.coeffs), domain_4n);
        let q_r_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_r_poly.coeffs), domain_4n);
        let q_o_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_o_poly.coeffs), domain_4n);
        let q_c_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_c_poly.coeffs), domain_4n);

        // 3. Compute the sigma polynomials
        let (left_sigma_poly, right_sigma_poly, out_sigma_poly) =
            self.perm.compute_sigma_polynomials(self.n, domain);

        // 4. Commit to polynomials
        //
        let q_m_poly_commit = commit_key.commit(&q_m_poly, None).unwrap().0;
        let q_l_poly_commit = commit_key.commit(&q_l_poly, None).unwrap().0;
        let q_r_poly_commit = commit_key.commit(&q_r_poly, None).unwrap().0;
        let q_o_poly_commit = commit_key.commit(&q_o_poly, None).unwrap().0;
        let q_c_poly_commit = commit_key.commit(&q_c_poly, None).unwrap().0;

        let left_sigma_poly_commit = commit_key.commit(&left_sigma_poly, None).unwrap().0;
        let right_sigma_poly_commit = commit_key.commit(&right_sigma_poly, None).unwrap().0;
        let out_sigma_poly_commit = commit_key.commit(&out_sigma_poly, None).unwrap().0;

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
                (q_m_poly, q_m_poly_commit, q_m_eval_4n),
                (q_l_poly, q_l_poly_commit, q_l_eval_4n),
                (q_r_poly, q_r_poly_commit, q_r_eval_4n),
                (q_o_poly, q_o_poly_commit, q_o_eval_4n),
                (q_c_poly, q_c_poly_commit, q_c_eval_4n),
            ],
            left_sigma: (left_sigma_poly, left_sigma_poly_commit),
            right_sigma: (right_sigma_poly, right_sigma_poly_commit),
            out_sigma: (out_sigma_poly, out_sigma_poly_commit),
        }
    }

    // Prove will compute the pre-processed polynomials and
    // produce a proof
    fn prove(
        &mut self,
        commit_key: &ProverKey,
        preprocessed_circuit: &PreProcessedCircuit,
        transcript: &mut dyn TranscriptProtocol,
    ) -> Proof {
        let domain = EvaluationDomain::new(self.n).unwrap();

        //1. Compute witness Polynomials
        //
        // Convert Variables to Scalars
        let (w_l_scalar, w_r_scalar, w_o_scalar) = self
            .perm
            .witness_vars_to_scalars(&self.w_l, &self.w_r, &self.w_o);

        // Witnesses are now in evaluation form, convert them to coefficients
        // So that we may commit to them
        let w_l_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_l_scalar));
        let w_r_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_r_scalar));
        let w_o_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_o_scalar));

        // Commit to witness polynomials
        let w_l_poly_commit = commit_key.commit(&w_l_poly, None).unwrap().0;
        let w_r_poly_commit = commit_key.commit(&w_r_poly, None).unwrap().0;
        let w_o_poly_commit = commit_key.commit(&w_o_poly, None).unwrap().0;

        // Add commitment to witness polynomials to transcript
        transcript.append_commitment(b"w_l", &w_l_poly_commit);
        transcript.append_commitment(b"w_r", &w_r_poly_commit);
        transcript.append_commitment(b"w_o", &w_o_poly_commit);
        //

        // 2. Compute permutation polynomial
        //
        //
        // Compute permutation challenges; `beta` and `gamma`
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");
        //
        //
        let z_poly = self.perm.compute_permutation_poly(
            &domain,
            &w_l_scalar,
            &w_r_scalar,
            &w_o_scalar,
            &(beta, gamma),
        );
        // Commit to permutation polynomial
        //
        let z_poly_commit = commit_key.commit(&z_poly, None).unwrap().0;
        // Add commitment to permutation polynomials to transcript
        transcript.append_commitment(b"z", &z_poly_commit);
        //
        // 2. Compute public inputs polynomial
        let pi_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.public_inputs));
        //

        // 3. Compute quotient polynomial
        //
        // Compute quotient challenge; `alpha`
        let alpha = transcript.challenge_scalar(b"alpha");
        //
        let t_poly = quotient_poly::compute(
            &domain,
            &preprocessed_circuit,
            &z_poly,
            [&w_l_poly, &w_r_poly, &w_o_poly],
            &pi_poly,
            &(alpha, beta, gamma),
        );
        // Split quotient polynomial into 3 degree `n` polynomials
        // XXX: This implicitly assumes that the quotient polynomial will never go over
        // degree 3n. For custom gates, this may not hold true, unless the API restricts it
        let (t_low_poly, t_mid_poly, t_hi_poly) = self.split_tx_poly(domain.size(), &t_poly);

        // Commit to permutation polynomial
        //
        let t_low_commit = commit_key.commit(&t_low_poly, None).unwrap().0;
        let t_mid_commit = commit_key.commit(&t_mid_poly, None).unwrap().0;
        let t_hi_commit = commit_key.commit(&t_hi_poly, None).unwrap().0;
        // Add commitment to quotient polynomials to transcript
        transcript.append_commitment(b"t_lo", &t_low_commit);
        transcript.append_commitment(b"t_mid", &t_mid_commit);
        transcript.append_commitment(b"t_hi", &t_hi_commit);

        // 4. Compute linearisation polynomial
        //
        // Compute evaluation challenge; `z`
        let z_challenge = transcript.challenge_scalar(b"z");
        //
        let (lin_poly, evaluations) = linearisation_poly::compute(
            &domain,
            &preprocessed_circuit,
            &(alpha, beta, gamma, z_challenge),
            &w_l_poly,
            &w_r_poly,
            &w_o_poly,
            &t_poly,
            &z_poly,
        );
        // Add evaluations to transcript
        transcript.append_scalar(b"a_eval", &evaluations.proof.a_eval);
        transcript.append_scalar(b"b_eval", &evaluations.proof.b_eval);
        transcript.append_scalar(b"c_eval", &evaluations.proof.c_eval);
        transcript.append_scalar(b"left_sig_eval", &evaluations.proof.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &evaluations.proof.right_sigma_eval);
        transcript.append_scalar(b"perm_eval", &evaluations.proof.perm_eval);
        transcript.append_scalar(b"t_eval", &evaluations.quot_eval);
        transcript.append_scalar(b"r_eval", &evaluations.proof.lin_poly_eval);
        //

        // 5. Compute opening polynomial
        //
        // Compute opening challenge `v`
        let v = transcript.challenge_scalar(b"v");

        let (w_z_poly, w_zx_poly) = opening_poly::compute(
            domain.group_gen,
            domain.size(),
            z_challenge,
            &lin_poly,
            &evaluations,
            &t_low_poly,
            &t_mid_poly,
            &t_hi_poly,
            &w_l_poly,
            &w_r_poly,
            &w_o_poly,
            preprocessed_circuit.left_sigma_poly(),
            preprocessed_circuit.right_sigma_poly(),
            &z_poly,
            &v,
        );

        // Commit to opening polynomial
        let w_z_comm = commit_key.commit(&w_z_poly, None).unwrap().0;
        let w_z_x_comm = commit_key.commit(&w_zx_poly, None).unwrap().0;
        //
        // Create Proof
        Proof {
            a_comm: w_l_poly_commit,
            b_comm: w_r_poly_commit,
            c_comm: w_o_poly_commit,
            z_comm: z_poly_commit,
            t_lo_comm: t_low_commit,
            t_mid_comm: t_mid_commit,
            t_hi_comm: t_hi_commit,
            // Commitment to the opening polynomial
            w_z_comm: w_z_comm,
            // Commitment to the shifted opening polynomial
            w_zw_comm: w_z_x_comm,

            evaluations: evaluations.proof,
        }
    }

    fn circuit_size(&self) -> usize {
        self.n
    }
}

impl StandardComposer {
    pub fn new() -> Self {
        StandardComposer::with_expected_size(0)
    }

    // Split `t(X)` poly into three degree-n polynomials.
    pub fn split_tx_poly(
        &self,
        n: usize,
        t_x: &Polynomial,
    ) -> (Polynomial, Polynomial, Polynomial) {
        (
            Polynomial::from_coefficients_vec(t_x[0..n].to_vec()),
            Polynomial::from_coefficients_vec(t_x[n..2 * n].to_vec()),
            Polynomial::from_coefficients_vec(t_x[2 * n..].to_vec()),
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
        let zero_scalar = Scalar::zero();
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
    pub fn add_input(&mut self, s: Scalar) -> Variable {
        self.perm.new_variable(s)
    }
    // evaluates a linear combination
    pub(crate) fn eval(&self, lc: LinearCombination) -> Scalar {
        let mut sum = Scalar::zero();
        for (variable, scalar) in lc.terms.iter() {
            let value = self.perm.variables[variable];
            sum += &(value * scalar);
        }
        sum
    }
    // Evaluates a linear combination and adds it's value to the constraint system
    fn add_lc(&mut self, lc: LinearCombination) -> Variable {
        let eval = self.eval(lc);
        self.add_input(eval)
    }
    // Adds an add gate to the circuit
    pub fn add_gate(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
        q_l: Scalar,
        q_r: Scalar,
        q_o: Scalar,
        q_c: Scalar,
        pi: Scalar,
    ) -> (Variable, Variable, Variable) {
        let l = self.add_lc(a);
        let r = self.add_lc(b);
        let o = self.add_lc(c);

        self.w_l.push(l);
        self.w_r.push(r);
        self.w_o.push(o);

        // For an add gate, q_m is zero
        self.q_m.push(Scalar::zero());

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

    pub fn mul_gate(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
        q_m: Scalar,
        q_o: Scalar,
        q_c: Scalar,
        pi: Scalar,
    ) -> (Variable, Variable, Variable) {
        let l = self.add_lc(a);
        let r = self.add_lc(b);
        let o = self.add_lc(c);

        self.w_l.push(l);
        self.w_r.push(r);
        self.w_o.push(o);

        // For a mul gate q_L and q_R is zero
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());

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
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
        q_m: Scalar,
        q_l: Scalar,
        q_r: Scalar,
        q_o: Scalar,
        q_c: Scalar,
        pi: Scalar,
    ) -> (Variable, Variable, Variable) {
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
        a: LinearCombination,
        constant: Scalar,
        pi: Scalar,
    ) -> Variable {
        let (a, _, _) = self.add_gate(
            a.clone(),
            a.clone(),
            a,
            Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            -constant,
            pi,
        );
        a
    }

    pub fn bool_gate(&mut self, a: LinearCombination) -> Variable {
        let lro = self.add_lc(a);

        self.w_l.push(lro);
        self.w_r.push(lro);
        self.w_o.push(lro);

        self.q_m.push(Scalar::one());
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        self.q_o.push(-Scalar::one());
        self.q_c.push(Scalar::zero());

        self.public_inputs.push(Scalar::zero());

        self.perm.add_variable_to_map(lro, lro, lro, self.n);

        self.n = self.n + 1;

        lro
    }

    pub fn add_dummy_constraints(&mut self) {
        // Add a dummy constraint so that we do not have zero polynomials
        self.q_m.push(Scalar::from(1));
        self.q_l.push(Scalar::from(2));
        self.q_r.push(Scalar::from(3));
        self.q_o.push(Scalar::from(4));
        self.q_c.push(Scalar::from(5));
        self.public_inputs.push(Scalar::zero());
        let var_six = self.add_input(Scalar::from(6));
        let var_seven = self.add_input(Scalar::from(7));
        let var_min_twenty = self.add_input(-Scalar::from(20));
        self.w_l.push(var_six);
        self.w_r.push(var_seven);
        self.w_o.push(var_min_twenty);
        self.perm
            .add_variable_to_map(var_six, var_seven, var_min_twenty, self.n);
        self.n = self.n + 1;
        //Add another dummy constraint so that we do not get the identity permutation
        self.q_m.push(Scalar::from(1));
        self.q_l.push(Scalar::from(1));
        self.q_r.push(Scalar::from(1));
        self.q_o.push(Scalar::from(1));
        self.q_c.push(Scalar::from(127));
        self.public_inputs.push(Scalar::zero());
        self.w_l.push(var_min_twenty);
        self.w_r.push(var_six);
        self.w_o.push(var_seven);
        self.perm
            .add_variable_to_map(var_min_twenty, var_six, var_seven, self.n);
        self.n = self.n + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment_scheme::kzg10::SRS;
    use bls12_381::Scalar as Fr;
    use merlin::Transcript;
    // Ensures a + b - c = 0
    fn simple_add_gadget(
        composer: &mut StandardComposer,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
        pi: Scalar,
    ) {
        let q_l = Scalar::one();
        let q_r = Scalar::one();
        let q_o = -Scalar::one();
        let q_c = Scalar::zero();

        composer.add_gate(a.into(), b.into(), c.into(), q_l, q_r, q_o, q_c, pi);
    }

    fn example_gadget(
        composer: &mut StandardComposer,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
    ) {
        composer.mul_gate(
            a,
            b,
            c,
            Scalar::one(),
            -Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
        );
    }

    // Returns a composer with `n` constraints
    fn add_dummy_composer(n: usize) -> StandardComposer {
        let mut composer = StandardComposer::new();

        let one = Scalar::one();

        let var_one = composer.add_input(one);
        let var_two: LinearCombination =
            LinearCombination::from(var_one) + LinearCombination::from(var_one);

        for _ in 0..n {
            simple_add_gadget(
                &mut composer,
                var_one.into(),
                var_one.into(),
                var_two.clone(),
                Scalar::zero(),
            );
        }
        composer.add_dummy_constraints();

        composer
    }

    #[test]
    fn test_pad() {
        let num_constraints = 100;
        let mut composer: StandardComposer = add_dummy_composer(num_constraints);

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
        let ok = test_gadget(
            |_| {
                // do nothing except add the dummy constraints
            },
            200,
        );
        assert!(ok);
    }

    #[test]
    fn test_pi() {
        let ok = test_gadget(
            |mut composer| {
                let var_one = composer.add_input(Fr::one());
                let var_three = composer.add_input(Fr::from(3));
                let var_four = composer.add_input(Fr::from(4));
                simple_add_gadget(
                    &mut composer,
                    var_one.into(),
                    var_one.into(),
                    var_three.into(),
                    Fr::one(),
                );
                simple_add_gadget(
                    &mut composer,
                    var_one.into(),
                    var_one.into(),
                    var_four.into(),
                    Fr::from(2),
                );
            },
            200,
        );
        assert!(ok);
    }

    #[test]
    fn test_correct_add_mul_gate() {
        let ok = test_gadget(
            |mut composer| {
                // Verify that (4+5) * (6+7) = 117
                let four: LinearCombination = composer.add_input(Fr::from(4)).into();
                let five: LinearCombination = composer.add_input(Fr::from(5)).into();
                let six: LinearCombination = composer.add_input(Fr::from(6)).into();
                let seven: LinearCombination = composer.add_input(Fr::from(7)).into();
                let one_seventeen = composer.add_input(Fr::from(117));
                example_gadget(
                    &mut composer,
                    four + five,
                    six + seven,
                    one_seventeen.into(),
                );
            },
            200,
        );
        assert!(ok);
    }
    #[test]
    fn test_incorrect_add_mul_gate() {
        let ok = test_gadget(
            |mut composer| {
                // Verify that (5+5) * (6+7) != 117
                let four: LinearCombination = composer.add_input(Fr::from(5)).into();
                let five: LinearCombination = composer.add_input(Fr::from(5)).into();
                let six: LinearCombination = composer.add_input(Fr::from(6)).into();
                let seven: LinearCombination = composer.add_input(Fr::from(7)).into();
                let one_seventeen = composer.add_input(Fr::from(117));
                example_gadget(
                    &mut composer,
                    four + five,
                    six + seven,
                    one_seventeen.into(),
                );
            },
            200,
        );
        assert!(!ok);
    }

    #[test]
    fn test_correct_bool_gate() {
        let ok = test_gadget(
            |composer| {
                let zero = composer.add_input(Fr::zero());
                let one = composer.add_input(Fr::one());

                composer.bool_gate(zero.into());
                composer.bool_gate(one.into());
            },
            32,
        );
        assert!(ok)
    }
    #[test]
    fn test_incorrect_bool_gate() {
        let ok = test_gadget(
            |composer| {
                let zero = composer.add_input(Fr::from(5));
                let one = composer.add_input(Fr::one());

                composer.bool_gate(zero.into());
                composer.bool_gate(one.into());
            },
            32,
        );
        assert!(!ok)
    }

    fn test_gadget(gadget: fn(composer: &mut StandardComposer), n: usize) -> bool {
        // Common View
        let public_parameters = SRS::setup(2 * n, &mut rand::thread_rng()).unwrap();
        // Provers View                                                                             //
        let (proof, public_inputs) = {
            let mut composer: StandardComposer = add_dummy_composer(7);
            gadget(&mut composer);

            let (ck, _) = public_parameters
                .trim(2 * composer.circuit_size().next_power_of_two())
                .unwrap();
            let domain = EvaluationDomain::new(composer.circuit_size()).unwrap();
            let mut transcript = Transcript::new(b"");
            // Preprocess circuit
            let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);
            (
                composer.prove(&ck, &preprocessed_circuit, &mut transcript),
                composer.public_inputs,
            )
        };
        // Verifiers view
        //
        let ok = {
            let mut composer: StandardComposer = add_dummy_composer(7);
            gadget(&mut composer);

            let (ck, vk) = public_parameters
                .trim(composer.circuit_size().next_power_of_two())
                .unwrap();
            let domain = EvaluationDomain::new(composer.circuit_size()).unwrap();
            // setup transcript
            let mut transcript = Transcript::new(b"");
            // Preprocess circuit
            let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);
            // Verify proof
            proof.verify(&preprocessed_circuit, &mut transcript, &vk, &public_inputs)
        };
        ok
    }

    #[test]
    fn test_circuit_size() {
        let mut composer: StandardComposer = StandardComposer::new();

        let one = Fr::one();
        let two = one + &one;

        let var_one = composer.add_input(one);
        let var_two = composer.add_input(two);

        let n = 20;

        for _ in 0..n {
            simple_add_gadget(
                &mut composer,
                var_one.into(),
                var_one.into(),
                var_two.into(),
                Fr::zero(),
            );
        }

        assert_eq!(n, composer.circuit_size())
    }
}
