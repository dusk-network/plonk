// Gate fn's have a big number of attributes but
// it is intended to be like this in order to provide
// maximum performance and minimum circuit sizes.
#![allow(clippy::too_many_arguments)]
use super::linearisation_poly;
use super::quotient_poly;
use super::{proof::Proof, Composer, PreProcessedCircuit};
use crate::commitment_scheme::kzg10::ProverKey;
use crate::constraint_system::widget::{ArithmeticWidget, PermutationWidget, RangeWidget};
use crate::constraint_system::Variable;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::permutation::Permutation;
use crate::transcript::TranscriptProtocol;
use bls12_381::Scalar;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::HashMap;

/// A composer is a circuit builder
/// and will dictate how a circuit is built
/// We will have a default Composer called `StandardComposer`
#[derive(Debug)]
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
    // fourth wire selector
    q_4: Vec<Scalar>,
    // constant wire selector
    q_c: Vec<Scalar>,
    // arithmetic wire selector
    q_arith: Vec<Scalar>,
    // range selector
    q_range: Vec<Scalar>,

    public_inputs: Vec<Scalar>,

    // witness vectors
    w_l: Vec<Variable>,
    w_r: Vec<Variable>,
    w_o: Vec<Variable>,
    w_4: Vec<Variable>,

    // We reserve a variable to be zero in the system
    // This is so that when a gate only uses three, we set the fourth wire to be
    // the variable that references zero
    zero_var: Variable,

    // These are the actual variable values
    // N.B. They should not be exposed to the end user once added into the composer
    pub(crate) variables: HashMap<Variable, Scalar>,

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
        assert!(self.q_4.len() == k);
        assert!(self.q_arith.len() == k);
        assert!(self.q_range.len() == k);
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
        let q_4_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_4));
        let q_arith_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_arith));
        let q_range_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_range));

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
        let q_4_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_4_poly.coeffs), domain_4n);
        let q_arith_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_arith_poly.coeffs), domain_4n);
        let q_range_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_range_poly.coeffs), domain_4n);

        // 3. Compute the sigma polynomials
        let (left_sigma_poly, right_sigma_poly, out_sigma_poly, fourth_sigma_poly) =
            self.perm.compute_sigma_polynomials(self.n, domain);

        // 3a. Compute 4n evaluations of sigma polynomials and the linear polynomial
        let left_sigma_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&left_sigma_poly.coeffs),
            domain_4n,
        );
        let right_sigma_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&right_sigma_poly.coeffs),
            domain_4n,
        );
        let out_sigma_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&out_sigma_poly.coeffs),
            domain_4n,
        );
        let fourth_sigma_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&fourth_sigma_poly.coeffs),
            domain_4n,
        );
        let linear_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&[Scalar::zero(), Scalar::one()]),
            domain_4n,
        );

        // 4. Commit to polynomials
        //
        let q_m_poly_commit = commit_key.commit(&q_m_poly).unwrap();
        let q_l_poly_commit = commit_key.commit(&q_l_poly).unwrap();
        let q_r_poly_commit = commit_key.commit(&q_r_poly).unwrap();
        let q_o_poly_commit = commit_key.commit(&q_o_poly).unwrap();
        let q_c_poly_commit = commit_key.commit(&q_c_poly).unwrap();
        let q_4_poly_commit = commit_key.commit(&q_4_poly).unwrap();
        let q_arith_poly_commit = commit_key.commit(&q_arith_poly).unwrap();
        let q_range_poly_commit = commit_key.commit(&q_range_poly).unwrap();

        let left_sigma_poly_commit = commit_key.commit(&left_sigma_poly).unwrap();
        let right_sigma_poly_commit = commit_key.commit(&right_sigma_poly).unwrap();
        let out_sigma_poly_commit = commit_key.commit(&out_sigma_poly).unwrap();
        let fourth_sigma_poly_commit = commit_key.commit(&fourth_sigma_poly).unwrap();

        //5. Add polynomial commitments to transcript
        //
        transcript.append_commitment(b"q_m", &q_m_poly_commit);
        transcript.append_commitment(b"q_l", &q_l_poly_commit);
        transcript.append_commitment(b"q_r", &q_r_poly_commit);
        transcript.append_commitment(b"q_o", &q_o_poly_commit);
        transcript.append_commitment(b"q_c", &q_c_poly_commit);
        transcript.append_commitment(b"q_4", &q_4_poly_commit);
        transcript.append_commitment(b"q_arith", &q_arith_poly_commit);
        transcript.append_commitment(b"q_range", &q_range_poly_commit);

        transcript.append_commitment(b"left_sigma", &left_sigma_poly_commit);
        transcript.append_commitment(b"right_sigma", &right_sigma_poly_commit);
        transcript.append_commitment(b"out_sigma", &out_sigma_poly_commit);
        transcript.append_commitment(b"fourth_sigma", &fourth_sigma_poly_commit);

        // Append circuit size to transcript
        transcript.circuit_domain_sep(self.circuit_size() as u64);

        let arithmetic_widget = ArithmeticWidget::new((
            (q_m_poly, q_m_poly_commit, Some(q_m_eval_4n)),
            (q_l_poly, q_l_poly_commit, Some(q_l_eval_4n)),
            (q_r_poly, q_r_poly_commit, Some(q_r_eval_4n)),
            (q_o_poly, q_o_poly_commit, Some(q_o_eval_4n)),
            (q_c_poly, q_c_poly_commit, Some(q_c_eval_4n)),
            (q_4_poly, q_4_poly_commit, Some(q_4_eval_4n)),
            (q_arith_poly, q_arith_poly_commit, Some(q_arith_eval_4n)),
        ));

        let range_widget =
            RangeWidget::new((q_range_poly, q_range_poly_commit, Some(q_range_eval_4n)));

        let perm_widget = PermutationWidget::new(
            (
                left_sigma_poly,
                left_sigma_poly_commit,
                Some(left_sigma_eval_4n),
            ),
            (
                right_sigma_poly,
                right_sigma_poly_commit,
                Some(right_sigma_eval_4n),
            ),
            (
                out_sigma_poly,
                out_sigma_poly_commit,
                Some(out_sigma_eval_4n),
            ),
            (
                fourth_sigma_poly,
                fourth_sigma_poly_commit,
                Some(fourth_sigma_eval_4n),
            ),
            linear_eval_4n,
        );

        PreProcessedCircuit {
            n: self.n,
            arithmetic: arithmetic_widget,
            range: range_widget,
            permutation: perm_widget,
            // Compute 4n evaluations for X^n -1
            v_h_coset_4n: domain_4n.compute_vanishing_poly_over_coset(domain.size() as u64),
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
        let w_l_scalar = self.to_scalars(&self.w_l);
        let w_r_scalar = self.to_scalars(&self.w_r);
        let w_o_scalar = self.to_scalars(&self.w_o);
        let w_4_scalar = self.to_scalars(&self.w_4);

        // Witnesses are now in evaluation form, convert them to coefficients
        // So that we may commit to them
        let w_l_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_l_scalar));
        let w_r_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_r_scalar));
        let w_o_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_o_scalar));
        let w_4_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_4_scalar));

        // Commit to witness polynomials
        let w_l_poly_commit = commit_key.commit(&w_l_poly).unwrap();
        let w_r_poly_commit = commit_key.commit(&w_r_poly).unwrap();
        let w_o_poly_commit = commit_key.commit(&w_o_poly).unwrap();
        let w_4_poly_commit = commit_key.commit(&w_4_poly).unwrap();

        // Add witness polynomial commitments to transcript
        transcript.append_commitment(b"w_l", &w_l_poly_commit);
        transcript.append_commitment(b"w_r", &w_r_poly_commit);
        transcript.append_commitment(b"w_o", &w_o_poly_commit);
        transcript.append_commitment(b"w_4", &w_4_poly_commit);

        // 2. Compute permutation polynomial
        //
        //
        // Compute permutation challenges; `beta` and `gamma`
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");

        let z_poly = self.perm.compute_permutation_poly(
            &domain,
            &w_l_scalar,
            &w_r_scalar,
            &w_o_scalar,
            &w_4_scalar,
            &(beta, gamma),
        );

        // Commit to permutation polynomial
        //
        let z_poly_commit = commit_key.commit(&z_poly).unwrap();

        // Add permutation polynomial commitment to transcript
        transcript.append_commitment(b"z", &z_poly_commit);

        // 3. Compute public inputs polynomial
        let pi_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.public_inputs));

        // 4. Compute quotient polynomial
        //
        // Compute quotient challenge; `alpha`
        let alpha = transcript.challenge_scalar(b"alpha");

        let t_poly = quotient_poly::compute(
            &domain,
            &preprocessed_circuit,
            &z_poly,
            (&w_l_poly, &w_r_poly, &w_o_poly, &w_4_poly),
            &pi_poly,
            &(alpha, beta, gamma),
        );

        // Split quotient polynomial into 4 degree `n` polynomials
        let (t_1_poly, t_2_poly, t_3_poly, t_4_poly) = self.split_tx_poly(domain.size(), &t_poly);

        // Commit to splitted quotient polynomial
        let t_1_commit = commit_key.commit(&t_1_poly).unwrap();
        let t_2_commit = commit_key.commit(&t_2_poly).unwrap();
        let t_3_commit = commit_key.commit(&t_3_poly).unwrap();
        let t_4_commit = commit_key.commit(&t_4_poly).unwrap();

        // Add quotient polynomial commitments to transcript
        transcript.append_commitment(b"t_1", &t_1_commit);
        transcript.append_commitment(b"t_2", &t_2_commit);
        transcript.append_commitment(b"t_3", &t_3_commit);
        transcript.append_commitment(b"t_4", &t_4_commit);

        // 4. Compute linearisation polynomial
        //
        // Compute evaluation challenge; `z`
        let z_challenge = transcript.challenge_scalar(b"z");

        let (lin_poly, evaluations) = linearisation_poly::compute(
            &domain,
            &preprocessed_circuit,
            &(alpha, beta, gamma, z_challenge),
            &w_l_poly,
            &w_r_poly,
            &w_o_poly,
            &w_4_poly,
            &t_poly,
            &z_poly,
        );

        // Add evaluations to transcript
        transcript.append_scalar(b"a_eval", &evaluations.proof.a_eval);
        transcript.append_scalar(b"b_eval", &evaluations.proof.b_eval);
        transcript.append_scalar(b"c_eval", &evaluations.proof.c_eval);
        transcript.append_scalar(b"d_eval", &evaluations.proof.d_eval);
        transcript.append_scalar(b"d_next_eval", &evaluations.proof.d_next_eval);
        transcript.append_scalar(b"left_sig_eval", &evaluations.proof.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &evaluations.proof.right_sigma_eval);
        transcript.append_scalar(b"out_sig_eval", &evaluations.proof.out_sigma_eval);
        transcript.append_scalar(b"q_arith_eval", &evaluations.proof.q_arith_eval);
        transcript.append_scalar(b"perm_eval", &evaluations.proof.perm_eval);
        transcript.append_scalar(b"t_eval", &evaluations.quot_eval);
        transcript.append_scalar(b"r_eval", &evaluations.proof.lin_poly_eval);

        // 5. Compute Openings using KZG10
        //
        // We merge the quotient polynomial using the `z_challenge` so the SRS is linear in the circuit size `n`
        let quot = Self::compute_quotient_opening_poly(
            domain.size(),
            &t_1_poly,
            &t_2_poly,
            &t_3_poly,
            &t_4_poly,
            &z_challenge,
        );

        // Compute aggregate witness to polynomials evaluated at the evaluation challenge `z`
        let aggregate_witness = commit_key.compute_aggregate_witness(
            &[
                quot,
                lin_poly,
                w_l_poly,
                w_r_poly,
                w_o_poly,
                w_4_poly.clone(),
                preprocessed_circuit
                    .permutation
                    .left_sigma
                    .polynomial
                    .clone(),
                preprocessed_circuit
                    .permutation
                    .right_sigma
                    .polynomial
                    .clone(),
                preprocessed_circuit
                    .permutation
                    .out_sigma
                    .polynomial
                    .clone(),
            ],
            &z_challenge,
            transcript,
        );
        let w_z_comm = commit_key.commit(&aggregate_witness).unwrap();

        // Compute aggregate witness to polynomials evaluated at the shifted evaluation challenge
        let shifted_aggregate_witness = commit_key.compute_aggregate_witness(
            &[z_poly, w_4_poly],
            &(z_challenge * domain.group_gen),
            transcript,
        );
        let w_zx_comm = commit_key.commit(&shifted_aggregate_witness).unwrap();

        // Create Proof
        Proof {
            a_comm: w_l_poly_commit,
            b_comm: w_r_poly_commit,
            c_comm: w_o_poly_commit,
            d_comm: w_4_poly_commit,

            z_comm: z_poly_commit,

            t_1_comm: t_1_commit,
            t_2_comm: t_2_commit,
            t_3_comm: t_3_commit,
            t_4_comm: t_4_commit,

            w_z_comm,
            w_zw_comm: w_zx_comm,

            evaluations: evaluations.proof,
        }
    }

    fn circuit_size(&self) -> usize {
        self.n
    }
}

impl Default for StandardComposer {
    fn default() -> Self {
        Self::new()
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
    ) -> (Polynomial, Polynomial, Polynomial, Polynomial) {
        (
            Polynomial::from_coefficients_vec(t_x[0..n].to_vec()),
            Polynomial::from_coefficients_vec(t_x[n..2 * n].to_vec()),
            Polynomial::from_coefficients_vec(t_x[2 * n..3 * n].to_vec()),
            Polynomial::from_coefficients_vec(t_x[3 * n..].to_vec()),
        )
    }
    /// Fixes a variable in the witness to be a part of the circuit description
    /// This method is (currently) only used in the following context:
    /// We have gates which only require 3/4 wires,
    /// We must assign the fourth value a value, we fix this value to be zero
    /// However, the verifier needs to be able to verify that this value is also zero
    /// So we must make this zero value a part of the circuit description of every circuit
    fn add_witness_to_circuit_description(&mut self, var: Variable, value: Scalar) {
        self.poly_gate(
            var,
            var,
            var,
            Scalar::zero(),
            Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            -value,
            Scalar::zero(),
        );
    }

    /// Convert variables to their actual witness values
    pub(crate) fn to_scalars(&self, vars: &[Variable]) -> Vec<Scalar> {
        vars.par_iter().map(|var| self.variables[var]).collect()
    }

    fn compute_quotient_opening_poly(
        n: usize,
        t_1_poly: &Polynomial,
        t_2_poly: &Polynomial,
        t_3_poly: &Polynomial,
        t_4_poly: &Polynomial,
        z_challenge: &Scalar,
    ) -> Polynomial {
        // Compute z^n , z^2n , z^3n
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
        let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);

        let a = t_1_poly;
        let b = t_2_poly * &z_n;
        let c = t_3_poly * &z_two_n;
        let d = t_4_poly * &z_three_n;
        let abc = &(a + &b) + &c;
        &abc + &d
    }

    // Creates a new circuit with an expected circuit size
    // This will allow for less reallocations when building the circuit
    pub fn with_expected_size(expected_size: usize) -> Self {
        let mut composer = StandardComposer {
            n: 0,

            q_m: Vec::with_capacity(expected_size),
            q_l: Vec::with_capacity(expected_size),
            q_r: Vec::with_capacity(expected_size),
            q_o: Vec::with_capacity(expected_size),
            q_c: Vec::with_capacity(expected_size),
            q_4: Vec::with_capacity(expected_size),
            q_arith: Vec::with_capacity(expected_size),
            q_range: Vec::with_capacity(expected_size),
            public_inputs: Vec::with_capacity(expected_size),

            w_l: Vec::with_capacity(expected_size),
            w_r: Vec::with_capacity(expected_size),
            w_o: Vec::with_capacity(expected_size),
            w_4: Vec::with_capacity(expected_size),

            zero_var: Variable(0),

            variables: HashMap::with_capacity(expected_size),

            perm: Permutation::new(),
        };

        // Reserve the first variable to be zero
        let zero_var = composer.add_input(Scalar::zero());
        composer.add_witness_to_circuit_description(zero_var, Scalar::zero());
        composer.zero_var = zero_var;

        composer
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
        self.q_4.extend(zeroes_scalar.iter());
        self.q_arith.extend(zeroes_scalar.iter());
        self.q_range.extend(zeroes_scalar.iter());

        self.w_l.extend(zeroes_var.iter());
        self.w_r.extend(zeroes_var.iter());
        self.w_o.extend(zeroes_var.iter());
        self.w_4.extend(zeroes_var.iter());

        self.n += diff;
    }

    /// Add Input first calls the `Permutation` struct
    /// to generate and allocate a new variable `var`
    /// The composer then links the Variable to the Scalar
    /// and returns the Variable for use in the system.
    pub fn add_input(&mut self, s: Scalar) -> Variable {
        // Get a new Variable from the permutation
        let var = self.perm.new_variable();
        // The composer now links the Scalar to the Variable returned from the Permutation
        self.variables.insert(var, s);

        var
    }

    // Adds a width-3 add gate to the circuit
    pub fn add_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_l: Scalar,
        q_r: Scalar,
        q_o: Scalar,
        q_c: Scalar,
        pi: Scalar,
    ) -> Variable {
        self.big_add_gate(
            a,
            b,
            c,
            self.zero_var,
            q_l,
            q_r,
            q_o,
            Scalar::zero(),
            q_c,
            pi,
        )
    }

    // Ensures q_l * a + q_r * b - c = 0
    // Returns c
    pub fn add(
        &mut self,
        q_l_a: (Scalar, Variable),
        q_r_b: (Scalar, Variable),
        pi: Scalar,
    ) -> Variable {
        self.big_add(q_l_a, q_r_b, (Scalar::zero(), self.zero_var), pi)
    }
    // Ensures q_l * a + q_r * b * q_4 * d - c = 0
    // Returns c
    pub fn big_add(
        &mut self,
        q_l_a: (Scalar, Variable),
        q_r_b: (Scalar, Variable),
        q_4_d: (Scalar, Variable),
        pi: Scalar,
    ) -> Variable {
        let q_l = q_l_a.0;
        let a = q_l_a.1;

        let q_r = q_r_b.0;
        let b = q_r_b.1;

        let q_4 = q_4_d.0;
        let d = q_4_d.1;

        let q_o = -Scalar::one();
        let q_c = Scalar::zero();

        // Compute the output wire
        let a_eval = self.variables[&a];
        let b_eval = self.variables[&b];
        let d_eval = self.variables[&d];
        let c_eval = (q_l * a_eval) + (q_r * b_eval) + (q_4 * d_eval) + pi;
        let c = self.add_input(c_eval);

        self.big_add_gate(a, b, c, d, q_l, q_r, q_o, q_4, q_c, pi)
    }

    // Adds a width-4 add gate to the circuit
    pub fn big_add_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        d: Variable,
        q_l: Scalar,
        q_r: Scalar,
        q_o: Scalar,
        q_4: Scalar,
        q_c: Scalar,
        pi: Scalar,
    ) -> Variable {
        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);
        self.w_4.push(d);

        // For an add gate, q_m is zero
        self.q_m.push(Scalar::zero());

        // Add selector vectors
        self.q_l.push(q_l);
        self.q_r.push(q_r);
        self.q_o.push(q_o);
        self.q_c.push(q_c);
        self.q_4.push(q_4);
        self.q_arith.push(Scalar::one());

        self.q_range.push(Scalar::zero());

        self.public_inputs.push(pi);

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }
    // Adds a width-3 mul gate
    pub fn mul_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_m: Scalar,
        q_o: Scalar,
        q_c: Scalar,
        pi: Scalar,
    ) -> Variable {
        self.big_mul_gate(a, b, c, self.zero_var, q_m, q_o, q_c, Scalar::zero(), pi)
    }

    //Adds a width-4 mul gate
    pub fn big_mul_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        d: Variable,
        q_m: Scalar,
        q_o: Scalar,
        q_c: Scalar,
        q_4: Scalar,
        pi: Scalar,
    ) -> Variable {
        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);
        self.w_4.push(d);

        // For a mul gate q_L and q_R is zero
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());

        // Add selector vectors
        self.q_m.push(q_m);
        self.q_o.push(q_o);
        self.q_c.push(q_c);
        self.q_4.push(q_4);
        self.q_arith.push(Scalar::one());

        self.q_range.push(Scalar::zero());

        self.public_inputs.push(pi);

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }

    // q_m * a * b - c = 0
    pub fn mul(&mut self, q_m: Scalar, a: Variable, b: Variable, pi: Scalar) -> Variable {
        self.big_mul(q_m, a, b, (Scalar::zero(), self.zero_var), pi)
    }

    // q_m * a * b + (q_4 * d) - c = 0
    // returns c
    pub fn big_mul(
        &mut self,
        q_m: Scalar,
        a: Variable,
        b: Variable,
        q_4_d: (Scalar, Variable),
        pi: Scalar,
    ) -> Variable {
        let q_o = -Scalar::one();
        let q_c = Scalar::zero();

        let q_4 = q_4_d.0;
        let d = q_4_d.1;

        // Compute output wire
        let a_eval = self.variables[&a];
        let b_eval = self.variables[&b];
        let d_eval = self.variables[&d];
        let c_eval = (q_m * a_eval * b_eval) + (q_4 * d_eval) + pi;
        let c = self.add_input(c_eval);

        self.big_mul_gate(a, b, c, d, q_m, q_o, q_c, q_4, pi)
    }

    // Adds a width-3 poly gate
    // We do not have a poly gate for width-4 as width-4 style gates are specialised
    pub fn poly_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_m: Scalar,
        q_l: Scalar,
        q_r: Scalar,
        q_o: Scalar,
        q_c: Scalar,
        pi: Scalar,
    ) -> (Variable, Variable, Variable) {
        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);
        self.w_4.push(self.zero_var);
        self.q_l.push(q_l);
        self.q_r.push(q_r);

        // Add selector vectors
        self.q_m.push(q_m);
        self.q_o.push(q_o);
        self.q_c.push(q_c);
        self.q_4.push(Scalar::zero());
        self.q_arith.push(Scalar::one());

        self.q_range.push(Scalar::zero());

        self.public_inputs.push(pi);

        self.perm
            .add_variables_to_map(a, b, c, self.zero_var, self.n);
        self.n += 1;

        (a, b, c)
    }

    pub fn constrain_to_constant(&mut self, a: Variable, constant: Scalar, pi: Scalar) {
        self.poly_gate(
            a,
            a,
            a,
            Scalar::zero(),
            Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            -constant,
            pi,
        );
    }

    pub fn bool_gate(&mut self, a: Variable) -> Variable {
        self.w_l.push(a);
        self.w_r.push(a);
        self.w_o.push(a);
        self.w_4.push(self.zero_var);

        self.q_m.push(Scalar::one());
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        self.q_o.push(-Scalar::one());
        self.q_c.push(Scalar::zero());
        self.q_4.push(Scalar::zero());
        self.q_arith.push(Scalar::one());

        self.q_range.push(Scalar::zero());

        self.public_inputs.push(Scalar::zero());

        self.perm
            .add_variables_to_map(a, a, a, self.zero_var, self.n);

        self.n += 1;

        a
    }

    pub fn range_gate(&mut self, witness: Variable, num_bits: usize) {
        use super::super::variable::WireData;
        use crate::bit_iterator::*;

        // Adds `variable` into the appropriate witness position
        // based on the accumulator number a_i
        let add_wire = |composer: &mut StandardComposer, i: usize, variable: Variable| {
            // Since four quads can fit into one gate, the gate index does not change for every four wires
            let gate_index = composer.n + (i / 4);

            let wire_data = match i % 4 {
                0 => {
                    composer.w_4.push(variable);
                    WireData::Fourth(gate_index)
                }
                1 => {
                    composer.w_o.push(variable);
                    WireData::Output(gate_index)
                }
                2 => {
                    composer.w_r.push(variable);
                    WireData::Right(gate_index)
                }
                3 => {
                    composer.w_l.push(variable);
                    WireData::Left(gate_index)
                }
                _ => unreachable!(),
            };
            composer.perm.add_variable_to_map(variable, wire_data);
        };

        // Note: A quad is a quaternary digit
        //
        // Number of bits should be even, this means that user must pad the number of bits external.
        assert!(num_bits % 2 == 0);

        // Convert witness to bit representation and reverse
        let value = self.variables[&witness];
        let bit_iter = BitIterator8::new(value.to_bytes());
        let mut bits: Vec<_> = bit_iter.collect();
        bits.reverse();

        // For a width-4 program, one gate will contain 4 accumulators
        // Each accumulator proves that a single quad is a base-4 digit.
        // Since there is 1-1 mapping between accumulators and quads
        // and quads contain 2 bits, one gate accumulates 8 bits.
        // We can therefore work out the number of gates needed;
        let mut num_gates = num_bits >> 3;

        // The number of bits may be divisible by 2 but not by 8.
        // Example: If we wanted to prove a number was within the range [0,2^10 -1 ]
        // We would need 10 bits. When dividing by 10 by 8, we will get 1 as the number of gates, when in fact we need 2 gates
        // In general, we will need to add an extra gate, if the number of bits is not divisible by 8
        if num_bits % 8 != 0 {
            num_gates += 1;
        }

        // Since each gate holds 4 quads, the number of quads that will be
        // needed to prove that the witness is within a specific range can be computed from the number of gates
        let num_quads = num_gates * 4;

        // There are now two things to note in terms of padding:
        // 1. (a_{i+1}, a_i) proves that {q_i+1} is a quaternary digit.
        // In order to prove that the first digit is a quad, we need to add a zero accumulator (genesis quad)
        // 2. We need the last gate to contain 1 quad, so the range gate equation is not used on the last gate.
        // This is needed because the range gate equation looks at the fourth for the next gate, which is not guaranteed to pass.
        // We therefore prepend quads until we have 1 quad in the last gate. This will at most add one extra gate.
        //
        // There are two cases to consider:
        // Case 1: If the number of bits used is divisible by 8, then it is also divisible by 4.
        // This means that we can find out how many gates are needed by dividing the number of bits by 8
        // However, since we will always need a genesis quad, it will mean that we will need an another gate to hold the extra quad
        // Example: Take 32 bits. We compute the number of gates to be 32/8 = 4 full gates, we then add 1 because we need the genesis accumulator
        // In this case, we only pad by one quad, which is the genesis quad. Moreover, the genesis quad is the quad that has added the extra gate.
        //
        // Case 2: When the number of bits is not divisible by 8
        // Since the number is not divisible by 4, as in case 1, when we add the genesis quad, we will have more than 1 quad on the last row
        // In this case, the genesis quad, did not add an extra gate. What will add the extra gate, is the padding.
        // We must apply padding in order ensure the last row has only one quad in on the fourth wire
        // In this case, it is the padding which will add an extra number of gates
        // Example: 34 bits requires 17 quads. We add one for the zeroed out accumulator. To make 18 quads. We can fit all of these quads in 5 gates.
        // 18 % 4 = 2 so on the last row, we will have two quads, which is bad.
        // We must pad the beginning in order to get one quad on the last row
        // We can work out how much we need to pad by the following equation
        // (18+X) % 4 = 1
        // X is 3 , so we pad 3 extra zeroes
        // We now have 21 quads in the system now and 21 / 4 = 5 remainder 1, so we will need 5 full gates and extra gate with 1 quad.
        let pad = 1 + (((num_quads << 1) - num_bits) >> 1);

        // The last observation; we will always use 1 more gate than the number of gates calculated
        // Either due to the genesis quad, or the padding used to ensure we have 1 quad on the last gate
        let used_gates = num_gates + 1;

        // We collect the set of accumulators to return back to the user
        // and keep a running count of the current accumulator
        let mut accumulators: Vec<Variable> = Vec::new();
        let mut accumulator = Scalar::zero();
        let four = Scalar::from(4);

        // First we pad our gates by the necessary amount
        for i in 0..pad {
            add_wire(self, i, self.zero_var);
        }

        for i in pad..=num_quads {
            // Convert each pair of bits to quads
            let bit_index = (num_quads - i) << 1;
            let q_0 = bits[bit_index] as u64;
            let q_1 = bits[bit_index + 1] as u64;
            let quad = q_0 + (2 * q_1);

            // Compute the next accumulator term
            accumulator = four * accumulator;
            accumulator += Scalar::from(quad);

            let accumulator_var = self.add_input(accumulator);
            accumulators.push(accumulator_var);

            add_wire(self, i, accumulator_var);
        }

        // Set the selector polynomials for all of the gates we used
        let zeros = vec![Scalar::zero(); used_gates];
        let ones = vec![Scalar::one(); used_gates];

        self.q_m.extend(zeros.iter());
        self.q_l.extend(zeros.iter());
        self.q_r.extend(zeros.iter());
        self.q_o.extend(zeros.iter());
        self.q_c.extend(zeros.iter());
        self.q_arith.extend(zeros.iter());
        self.q_4.extend(zeros.iter());
        self.q_range.extend(ones.iter());
        self.public_inputs.extend(zeros.iter());
        self.n += used_gates;

        // As mentioned above, we must switch off the range constraint for the last gate
        // Remember; it will contain one quad in the fourth wire, which will be used in the
        // gate before it
        // Furthermore, we set the left, right and output wires to zero
        *self.q_range.last_mut().unwrap() = Scalar::zero();
        self.w_l.push(self.zero_var);
        self.w_r.push(self.zero_var);
        self.w_o.push(self.zero_var);

        // Lastly, we must link the last accumulator value to the initial witness
        // This last constraint will pass as long as
        // - The witness is within the number of bits initially specified
        let last_accumulator = accumulators.len() - 1;
        self.assert_equal(accumulators[last_accumulator], witness);
        accumulators[last_accumulator] = witness;
    }

    /// Asserts that two variables are the same
    /// XXX: Instead of wasting a gate, we can use the permutation polynomial to do this
    pub fn assert_equal(&mut self, a: Variable, b: Variable) {
        self.poly_gate(
            a,
            b,
            self.zero_var,
            Scalar::zero(),
            Scalar::one(),
            -Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
        );
    }

    pub fn add_dummy_constraints(&mut self) {
        // Add a dummy constraint so that we do not have zero polynomials
        self.q_m.push(Scalar::from(1));
        self.q_l.push(Scalar::from(2));
        self.q_r.push(Scalar::from(3));
        self.q_o.push(Scalar::from(4));
        self.q_c.push(Scalar::from(4));
        self.q_4.push(Scalar::one());
        self.q_arith.push(Scalar::one());
        self.q_range.push(Scalar::zero());
        self.public_inputs.push(Scalar::zero());
        let var_six = self.add_input(Scalar::from(6));
        let var_one = self.add_input(Scalar::from(1));
        let var_four = self.add_input(Scalar::from(4));
        let var_seven = self.add_input(Scalar::from(7));
        let var_min_twenty = self.add_input(-Scalar::from(20));
        self.w_l.push(var_six);
        self.w_r.push(var_seven);
        self.w_o.push(var_min_twenty);
        self.w_4.push(var_one);
        self.perm
            .add_variables_to_map(var_six, var_seven, var_min_twenty, var_one, self.n);
        self.n += 1;
        //Add another dummy constraint so that we do not get the identity permutation
        self.q_m.push(Scalar::from(1));
        self.q_l.push(Scalar::from(1));
        self.q_r.push(Scalar::from(1));
        self.q_o.push(Scalar::from(1));
        self.q_c.push(Scalar::from(127));
        self.q_4.push(Scalar::zero());
        self.q_arith.push(Scalar::one());
        self.q_range.push(Scalar::zero());
        self.public_inputs.push(Scalar::zero());
        self.w_l.push(var_min_twenty);
        self.w_r.push(var_six);
        self.w_o.push(var_seven);
        self.w_4.push(self.zero_var);
        self.perm
            .add_variables_to_map(var_min_twenty, var_six, var_seven, self.zero_var, self.n);
        self.n += 1;
        //Add another dummy constraint fro Q_range
        // XXX: We should have a way to handle the zero polynomial
        self.q_m.push(Scalar::zero());
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        self.q_o.push(Scalar::zero());
        self.q_c.push(Scalar::zero());
        self.q_4.push(Scalar::zero());
        self.q_arith.push(Scalar::zero());
        self.q_range.push(Scalar::one());
        self.public_inputs.push(Scalar::zero());
        self.w_l.push(var_one);
        self.w_r.push(self.zero_var);
        self.w_o.push(self.zero_var);
        self.w_4.push(self.zero_var);
        self.perm.add_variables_to_map(
            var_one,
            self.zero_var,
            self.zero_var,
            self.zero_var,
            self.n,
        );
        self.n += 1;
        // Previous gate will look at the d_next in this gate
        self.q_m.push(Scalar::zero());
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        self.q_o.push(Scalar::zero());
        self.q_c.push(Scalar::zero());
        self.q_4.push(Scalar::zero());
        self.q_arith.push(Scalar::zero());
        self.q_range.push(Scalar::zero());
        self.public_inputs.push(Scalar::zero());
        self.w_l.push(self.zero_var);
        self.w_r.push(self.zero_var);
        self.w_o.push(self.zero_var);
        self.w_4.push(var_four);
        self.perm.add_variables_to_map(
            self.zero_var,
            self.zero_var,
            self.zero_var,
            var_four,
            self.n,
        );
        self.n += 1;
    }

    #[allow(dead_code)]
    fn check_circuit_satisfied(&self) {
        let w_l = self.to_scalars(&self.w_l);
        let w_r = self.to_scalars(&self.w_r);
        let w_o = self.to_scalars(&self.w_o);
        let w_4 = self.to_scalars(&self.w_4);
        // Computes f(f-1)(f-2)(f-3)
        let delta = |f: Scalar| -> Scalar {
            let f_1 = f - Scalar::one();
            let f_2 = f - Scalar::from(2);
            let f_3 = f - Scalar::from(3);
            f * f_1 * f_2 * f_3
        };
        let four = Scalar::from(4);

        for i in 0..self.n {
            let qm = self.q_m[i];
            let ql = self.q_l[i];
            let qr = self.q_r[i];
            let qo = self.q_o[i];
            let qc = self.q_c[i];
            let q4 = self.q_4[i];
            let qarith = self.q_arith[i];
            let qrange = self.q_range[i];
            let pi = self.public_inputs[i];

            let a = w_l[i];
            let b = w_r[i];
            let c = w_o[i];
            let d = w_4[i];
            let d_next = w_4[(i + 1) % self.n];
            let k = qarith * ((qm * a * b) + (ql * a) + (qr * b) + (qo * c) + (q4 * d) + pi + qc)
                + qrange
                    * (delta(c - four * d)
                        + delta(b - four * c)
                        + delta(a - four * b)
                        + delta(d_next - four * a));

            assert_eq!(k, Scalar::zero(), "Check failed at gate {}", i,);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment_scheme::kzg10::PublicParameters;
    use bls12_381::Scalar as Fr;
    use merlin::Transcript;

    // Returns a composer with `n` constraints
    fn add_dummy_composer(n: usize) -> StandardComposer {
        let mut composer = StandardComposer::new();

        let one = Scalar::one();

        let var_one = composer.add_input(one);

        for _ in 0..n {
            composer.big_add(
                var_one.into(),
                var_one.into(),
                composer.zero_var.into(),
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
        assert!(composer.q_arith.len() == size);
        assert!(composer.q_range.len() == size);
        assert!(composer.w_l.len() == size);
        assert!(composer.w_r.len() == size);
        assert!(composer.w_o.len() == size);
    }

    #[test]
    fn test_prove_verify() {
        let ok = test_gadget(
            |composer| {
                // do nothing except add the dummy constraints
                composer.check_circuit_satisfied();
            },
            200,
        );
        assert!(ok);
    }

    #[test]
    fn test_range_constraint() {
        // Should fail as the number is not 32 bits
        let ok = test_gadget(
            |composer| {
                let witness = composer.add_input(Scalar::from((u32::max_value() as u64) + 1));
                composer.range_gate(witness, 32);
            },
            200,
        );
        assert!(!ok);

        // Should fail as number is greater than 32 bits
        let ok = test_gadget(
            |composer| {
                let witness = composer.add_input(Scalar::from(u64::max_value()));
                composer.range_gate(witness, 32);
            },
            200,
        );
        assert!(!ok);

        // Should pass as the number is within 34 bits
        let ok = test_gadget(
            |composer| {
                let witness = composer.add_input(Scalar::from(2u64.pow(34) - 1));
                composer.range_gate(witness, 34);
                composer.check_circuit_satisfied();
            },
            200,
        );
        assert!(ok);
    }

    #[test]
    #[should_panic]
    fn test_odd_bit_range() {
        // Should fail as the number we we need a even number of bits
        let _ok = test_gadget(
            |composer| {
                let witness = composer.add_input(Scalar::from(u32::max_value() as u64));
                composer.range_gate(witness, 33);
            },
            200,
        );
    }

    #[test]
    fn test_pi() {
        let ok = test_gadget(
            |composer| {
                let var_one = composer.add_input(Fr::one());

                let should_be_three = composer.big_add(
                    var_one.into(),
                    var_one.into(),
                    composer.zero_var.into(),
                    Scalar::one(),
                );
                composer.constrain_to_constant(should_be_three, Scalar::from(3), Scalar::zero());
                let should_be_four = composer.big_add(
                    var_one.into(),
                    var_one.into(),
                    composer.zero_var.into(),
                    Scalar::from(2),
                );
                composer.constrain_to_constant(should_be_four, Scalar::from(4), Scalar::zero());
            },
            200,
        );
        assert!(ok);
    }

    #[test]
    fn test_correct_add_mul_gate() {
        let ok = test_gadget(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) = 280
                let four = composer.add_input(Fr::from(4));
                let five = composer.add_input(Fr::from(5));
                let six = composer.add_input(Fr::from(6));
                let seven = composer.add_input(Fr::from(7));

                let fourteen =
                    composer.big_add(four.into(), five.into(), five.into(), Scalar::zero());

                composer.check_circuit_satisfied();

                let twenty =
                    composer.big_add(six.into(), seven.into(), seven.into(), Scalar::zero());

                // There are quite a few ways to check the equation is correct, depending on your circumstance
                // If we already have the output wire, we can constrain the output of the mul_gate to be equal to it
                // If we do not, we can compute it using the `mul`
                // If the output is public, we can also constrain the output wire of the mul gate to it. This is what this test does
                let output = composer.mul(Scalar::one(), fourteen, twenty, Scalar::zero());
                composer.constrain_to_constant(output, Scalar::from(280), Scalar::zero());
            },
            200,
        );
        assert!(ok);
    }

    #[test]
    fn test_correct_big_add_mul_gate() {
        let ok = test_gadget(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) + (8*9) = 352
                let four = composer.add_input(Fr::from(4));
                let five = composer.add_input(Fr::from(5));
                let six = composer.add_input(Fr::from(6));
                let seven = composer.add_input(Fr::from(7));
                let nine = composer.add_input(Fr::from(9));

                let fourteen =
                    composer.big_add(four.into(), five.into(), five.into(), Scalar::zero());

                let twenty =
                    composer.big_add(six.into(), seven.into(), seven.into(), Scalar::zero());

                let output = composer.big_mul(
                    Scalar::one(),
                    fourteen,
                    twenty,
                    (Scalar::from(8), nine),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(output, Scalar::from(352), Scalar::zero());
            },
            200,
        );
        assert!(ok);
    }

    #[test]
    fn test_incorrect_add_mul_gate() {
        let ok = test_gadget(
            |composer| {
                // Verify that (5+5) * (6+7) != 117
                let five = composer.add_input(Fr::from(5));
                let six = composer.add_input(Fr::from(6));
                let seven = composer.add_input(Fr::from(7));

                let five_plus_five = composer.big_add(
                    five.into(),
                    five.into(),
                    composer.zero_var.into(),
                    Scalar::zero(),
                );

                let six_plus_seven = composer.big_add(
                    six.into(),
                    seven.into(),
                    composer.zero_var.into(),
                    Scalar::zero(),
                );

                let output = composer.mul(
                    Scalar::one(),
                    five_plus_five,
                    six_plus_seven,
                    Scalar::zero(),
                );
                composer.constrain_to_constant(output, Scalar::from(117), Scalar::zero());
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

                composer.bool_gate(zero);
                composer.bool_gate(one);
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

                composer.bool_gate(zero);
                composer.bool_gate(one);
            },
            32,
        );
        assert!(!ok)
    }

    fn test_gadget(gadget: fn(composer: &mut StandardComposer), n: usize) -> bool {
        // Common View
        let public_parameters = PublicParameters::setup(2 * n, &mut rand::thread_rng()).unwrap();
        // Provers View
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

        let var_one = composer.add_input(Fr::one());

        let n = 20;

        for _ in 0..n {
            composer.big_add(
                var_one.into(),
                var_one.into(),
                composer.zero_var.into(),
                Scalar::zero(),
            );
        }

        // Circuit size is n+1 because we have an extra gate which forces the first witness to be zero
        assert_eq!(n + 1, composer.circuit_size())
    }
}
