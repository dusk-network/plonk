//! The `Composer` is a Trait that is actually defining some kind of
//! Circuit Builder for PLONK.
//!
//! In that sense, here we have the implementation of the `StandardComposer`
//! which has been designed in order to provide the maximum amount of performance
//! while having a big scope in utility terms.
//!
//! It allows us not only to build Add and Mul constraints but also to build
//! ECC op. gates, Range checks, Logical gates (Bitwise ops) etc.

// Gate fn's have a large number of attributes but
// it is intended to be like this in order to provide
// maximum performance and minimum circuit sizes.
#![allow(clippy::too_many_arguments)]
use super::cs_errors::PreProcessingError;
use crate::bit_iterator::*;
use crate::commitment_scheme::kzg10::CommitKey;

use crate::constraint_system::{Variable, WireData};
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::permutation::Permutation;
use crate::proof_system::widget::{ArithmeticWidget, LogicWidget, PermutationWidget, RangeWidget};
use crate::proof_system::PreProcessedCircuit;
use dusk_bls12_381::Scalar;
use failure::Error;
use jubjub::Fq;
use jubjub::Fr;
use jubjub::AffinePoint;
use jubjub::AffineNielsPoint;
use merlin::Transcript;
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
    // logic selector
    q_logic: Vec<Scalar>,

    pub(crate) public_inputs: Vec<Scalar>,

    // witness vectors
    pub(crate) w_l: Vec<Variable>,
    pub(crate) w_r: Vec<Variable>,
    pub(crate) w_o: Vec<Variable>,
    pub(crate) w_4: Vec<Variable>,

    /// A zero variable that is a part of the circuit description.
    /// We reserve a variable to be zero in the system
    /// This is so that when a gate only uses three wires, we set the fourth wire to be
    /// the variable that references zero
    pub zero_var: Variable,

    // These are the actual variable values
    // N.B. They should not be exposed to the end user once added into the composer
    pub(crate) variables: HashMap<Variable, Scalar>,

    pub(crate) perm: Permutation,
}

impl StandardComposer {
    /// Computes the pre-processed polynomials
    /// So the verifier can verify a proof made using this circuit
    pub fn preprocess(
        &mut self,
        commit_key: &CommitKey,
        transcript: &mut Transcript,
    ) -> Result<PreProcessedCircuit, Error> {
        let domain = EvaluationDomain::new(self.circuit_size())?;
        // Check that the lenght of the wires is consistent.
        self.check_poly_same_len()?;

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
        let q_logic_poly = Polynomial::from_coefficients_slice(&domain.ifft(&self.q_logic));

        // 2b. Compute 4n evaluations of selector polynomial
        let domain_4n = EvaluationDomain::new(4 * domain.size())?;
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
        let q_logic_eval_4n =
            Evaluations::from_vec_and_domain(domain_4n.coset_fft(&q_logic_poly.coeffs), domain_4n);

        // 3. Compute the sigma polynomials
        let (left_sigma_poly, right_sigma_poly, out_sigma_poly, fourth_sigma_poly) =
            self.perm.compute_sigma_polynomials(self.n, &domain);

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
        let q_m_poly_commit = commit_key.commit(&q_m_poly).unwrap_or_default();
        let q_l_poly_commit = commit_key.commit(&q_l_poly).unwrap_or_default();
        let q_r_poly_commit = commit_key.commit(&q_r_poly).unwrap_or_default();
        let q_o_poly_commit = commit_key.commit(&q_o_poly).unwrap_or_default();
        let q_c_poly_commit = commit_key.commit(&q_c_poly).unwrap_or_default();
        let q_4_poly_commit = commit_key.commit(&q_4_poly).unwrap_or_default();
        let q_arith_poly_commit = commit_key.commit(&q_arith_poly).unwrap_or_default();
        let q_range_poly_commit = commit_key.commit(&q_range_poly).unwrap_or_default();
        let q_logic_poly_commit = commit_key.commit(&q_logic_poly).unwrap_or_default();

        let left_sigma_poly_commit = commit_key.commit(&left_sigma_poly)?;
        let right_sigma_poly_commit = commit_key.commit(&right_sigma_poly)?;
        let out_sigma_poly_commit = commit_key.commit(&out_sigma_poly)?;
        let fourth_sigma_poly_commit = commit_key.commit(&fourth_sigma_poly)?;

        let arithmetic_widget = ArithmeticWidget::new((
            (q_m_poly, q_m_poly_commit, Some(q_m_eval_4n)),
            (q_l_poly, q_l_poly_commit, Some(q_l_eval_4n)),
            (q_r_poly, q_r_poly_commit, Some(q_r_eval_4n)),
            (q_o_poly, q_o_poly_commit, Some(q_o_eval_4n)),
            (q_c_poly.clone(), q_c_poly_commit, Some(q_c_eval_4n.clone())),
            (q_4_poly, q_4_poly_commit, Some(q_4_eval_4n)),
            (q_arith_poly, q_arith_poly_commit, Some(q_arith_eval_4n)),
        ));

        let range_widget =
            RangeWidget::new((q_range_poly, q_range_poly_commit, Some(q_range_eval_4n)));

        let logic_widget = LogicWidget::new(
            (q_c_poly, q_c_poly_commit, Some(q_c_eval_4n)),
            (q_logic_poly, q_logic_poly_commit, Some(q_logic_eval_4n)),
        );

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

        let ppc = PreProcessedCircuit {
            n: self.n,
            arithmetic: arithmetic_widget,
            range: range_widget,
            logic: logic_widget,
            permutation: perm_widget,
            // Compute 4n evaluations for X^n -1
            v_h_coset_4n: domain_4n.compute_vanishing_poly_over_coset(domain.size() as u64),
        };

        // Append commitments to transcript
        ppc.seed_transcript(transcript);

        Ok(ppc)
    }

    /// Returns the number of gates in the circuit
    pub fn circuit_size(&self) -> usize {
        self.n
    }

    /// Checks that all of the wires of the composer have the same
    /// length.
    fn check_poly_same_len(&self) -> Result<(), PreProcessingError> {
        let k = self.q_m.len();

        if self.q_o.len() == k
            && self.q_l.len() == k
            && self.q_r.len() == k
            && self.q_c.len() == k
            && self.q_4.len() == k
            && self.q_arith.len() == k
            && self.q_range.len() == k
            && self.q_logic.len() == k
            && self.w_l.len() == k
            && self.w_r.len() == k
            && self.w_o.len() == k
        {
            Ok(())
        } else {
            Err(PreProcessingError::MissmatchedPolyLen)
        }
    }
}

impl Default for StandardComposer {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardComposer {
    /// Generates a new empty `StandardComposer` with all of it's fields
    /// set to hold an initial capacity of 0.
    ///
    /// # Warning
    ///
    /// The usage of this may cause lots of re-allocations since the `Composer`
    /// holds `Vec` for every polynomial, and these will need to be re-allocated
    /// each time the circuit grows considerably.
    pub fn new() -> Self {
        StandardComposer::with_expected_size(0)
    }

    /// Returns the public inputs that the `StandardComposer` has stored until
    /// the time when this function is called as a `Vec<Scalar>`.
    #[cfg(feature = "trace")]
    pub fn public_inputs(&self) -> Vec<Scalar> {
        self.public_inputs.clone()
    }

    /// Fixes a variable in the witness to be a part of the circuit description.
    /// This method is (currently) only used in the following context:
    /// We have gates which only require 3/4 wires,
    /// We must assign the fourth value to another value, we then fix this value to be zero.
    /// However, the verifier needs to be able to verify that this value is also zero.
    /// We therefore must make this zero value a part of the circuit description of every circuit.
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

    /// Creates a new circuit with an expected circuit size.
    /// This will allow for less reallocations when building the circuit
    /// since the `Vec`s will already have an appropiate allocation at the
    /// beggining of the composing stage.
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
            q_logic: Vec::with_capacity(expected_size),
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

    /// Pads the circuit to the next power of two
    /// `diff` is the difference between circuit size and next power of two.
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
        self.q_logic.extend(zeroes_scalar.iter());

        self.w_l.extend(zeroes_var.iter());
        self.w_r.extend(zeroes_var.iter());
        self.w_o.extend(zeroes_var.iter());
        self.w_4.extend(zeroes_var.iter());

        self.n += diff;
    }

    /// Add Input first calls the `Permutation` struct
    /// to generate and allocate a new variable `var`.
    /// The composer then links the Variable to the Scalar
    /// and returns the Variable for use in the system.
    pub fn add_input(&mut self, s: Scalar) -> Variable {
        // Get a new Variable from the permutation
        let var = self.perm.new_variable();
        // The composer now links the Scalar to the Variable returned from the Permutation
        self.variables.insert(var, s);

        var
    }

    /// Adds a width-3 add gate to the circuit, linking the addition of the
    /// provided inputs, scaled by the selector coefficients with the output
    /// provided.
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

    /// Adds a `big_addition_gate` with the left and right inputs
    /// and it's scaling factors, computing & returning the output (result)
    /// `Variable`, and adding the corresponding addition constraint.
    ///
    /// This type of gate is usually used when we don't need to have
    /// the largest amount of performance as well as the minimum circuit-size
    /// possible. Since it defaults some of the selector coeffs = 0 in order
    /// to reduce the verbosity and complexity.
    ///
    /// Forces `q_l * w_l + q_r * w_r + q_c + PI = w_o(computed by the gate)`.
    pub fn add(
        &mut self,
        q_l_a: (Scalar, Variable),
        q_r_b: (Scalar, Variable),
        q_c: Scalar,
        pi: Scalar,
    ) -> Variable {
        self.big_add(q_l_a, q_r_b, (Scalar::zero(), self.zero_var), q_c, pi)
    }

    /// Adds a `big_addition_gate` with the left, right and fourth inputs
    /// and it's scaling factors, computing & returning the output (result)
    /// `Variable` and adding the corresponding addition constraint.
    ///
    /// This type of gate is usually used when we don't need to have
    /// the largets ammount of performance and the minimum circuit-size
    /// possible. Since it defaults some of the selector coeffs = 0 in order
    /// to reduce the verbosity and complexity.
    ///
    /// Forces `q_l * w_l + q_r * w_r + q_4 * w_4 + q_c + PI = w_o(computed by the gate)`.
    pub fn big_add(
        &mut self,
        q_l_a: (Scalar, Variable),
        q_r_b: (Scalar, Variable),
        q_4_d: (Scalar, Variable),
        q_c: Scalar,
        pi: Scalar,
    ) -> Variable {
        let q_l = q_l_a.0;
        let a = q_l_a.1;

        let q_r = q_r_b.0;
        let b = q_r_b.1;

        let q_4 = q_4_d.0;
        let d = q_4_d.1;

        let q_o = -Scalar::one();

        // Compute the output wire
        let a_eval = self.variables[&a];
        let b_eval = self.variables[&b];
        let d_eval = self.variables[&d];
        let c_eval = (q_l * a_eval) + (q_r * b_eval) + (q_4 * d_eval) + q_c + pi;
        let c = self.add_input(c_eval);

        self.big_add_gate(a, b, c, d, q_l, q_r, q_o, q_4, q_c, pi)
    }

    /// Adds a width-4 add gate to the circuit and it's corresponding
    /// constraint.
    ///
    /// This type of gate is usually used when we need to have
    /// the largest amount of performance and the minimum circuit-size
    /// possible. Since it allows the end-user to set every selector coefficient
    /// as scaling value on the gate eq.
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
        self.q_logic.push(Scalar::zero());

        self.public_inputs.push(pi);

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }
    /// Adds a width-3 add gate to the circuit linking the product of the
    /// provided inputs scaled by the selector coefficient `q_m` with the output
    /// provided scaled by `q_o`.
    ///
    /// Note that this gate requires to provide the actual result of the gate
    /// (output wire) since it will just add a `mul constraint` to the circuit.
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

    /// Adds a width-4 `big_mul_gate` with the left, right and fourth inputs
    /// and it's scaling factors, computing & returning the output (result)
    /// `Variable` and adding the corresponding mul constraint.
    ///
    /// This type of gate is usually used when we need to have
    /// the largest amount of performance and the minimum circuit-size
    /// possible. Since it allows the end-user to setup all of the selector
    /// coefficients.
    ///
    /// Forces `q_l * (w_l + w_r) + w_4 * q_4 + + q_c + PI = q_o * w_o(computed by the gate)`.
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
        self.q_logic.push(Scalar::zero());

        self.public_inputs.push(pi);

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }

    /// Adds a simple and basic addition to the circuit between to `Variable`s
    /// returning the resulting `Variable`.
    pub fn mul(
        &mut self,
        q_m: Scalar,
        a: Variable,
        b: Variable,
        q_c: Scalar,
        pi: Scalar,
    ) -> Variable {
        self.big_mul(q_m, a, b, (Scalar::zero(), self.zero_var), q_c, pi)
    }

    /// Adds a width-4 `big_mul_gate` with the left, right and fourth inputs
    /// and it's scaling factors, computing & returning the output (result)
    /// `Variable` and adding the corresponding mul constraint.
    ///
    /// This type of gate is usually used when we don't need to have
    /// the largest ammount of performance and the minimum circuit-size
    /// possible. Since it defaults some of the selector coeffs = 0 in order
    /// to reduce the verbosity and complexity.
    ///
    /// Forces `q_l * (w_l + w_r) + w_4 * q_4 + q_c + PI = w_o(computed by the gate)`.
    pub fn big_mul(
        &mut self,
        q_m: Scalar,
        a: Variable,
        b: Variable,
        q_4_d: (Scalar, Variable),
        q_c: Scalar,
        pi: Scalar,
    ) -> Variable {
        let q_o = -Scalar::one();

        let q_4 = q_4_d.0;
        let d = q_4_d.1;

        // Compute output wire
        let a_eval = self.variables[&a];
        let b_eval = self.variables[&b];
        let d_eval = self.variables[&d];
        let c_eval = (q_m * a_eval * b_eval) + (q_4 * d_eval) + q_c + pi;
        let c = self.add_input(c_eval);

        self.big_mul_gate(a, b, c, d, q_m, q_o, q_c, q_4, pi)
    }

    /// Adds a width-3 poly gate.
    /// This gate gives total freedom to the end user to implement the corresponding
    /// circuits in the most optimized way possible because the under has access to the
    /// whole set of variables, as well as selector coefficients that take part in the
    /// computation of the gate equation.
    ///
    /// The final constraint added will force the following:
    /// `(a * b) * q_m + a * q_l + b * q_r + q_c + PI + q_o * c = 0`.
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
        self.q_logic.push(Scalar::zero());

        self.public_inputs.push(pi);

        self.perm
            .add_variables_to_map(a, b, c, self.zero_var, self.n);
        self.n += 1;

        (a, b, c)
    }

    /// Adds a gate which is designed to constrain a `Variable` to have
    /// a specific constant value which is sent as a `Scalar`.
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

    /// Adds a boolean constraint (also known as binary constraint) where
    /// the gate eq. will enforce that the `Variable` received is either `0`
    /// or `1` by adding a constraint in the circuit.
    ///
    /// Note that using this constraint with whatever `Variable` that is not
    /// representing a value equalling 0 or 1, will always force the equation to fail.
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
        self.q_logic.push(Scalar::zero());

        self.public_inputs.push(Scalar::zero());

        self.perm
            .add_variables_to_map(a, a, a, self.zero_var, self.n);

        self.n += 1;

        a
    }

    /// Adds a range-constraint gate that checks and constrains a
    /// `Variable` to be inside of the range [0,num_bits].
    pub fn range_gate(&mut self, witness: Variable, num_bits: usize) {
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
        // We must apply padding in order to ensure the last row has only one quad in on the fourth wire
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
        self.q_logic.extend(zeros.iter());
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

    /// Performs a logical AND or XOR op between the inputs provided for the specified
    /// number of bits.
    ///
    /// Each logic gate adds `(num_bits / 2) + 1` gates to the circuit to perform the
    /// whole operation.
    ///
    /// ## Selector
    /// - is_xor_gate = 1 -> Performs XOR between the first `num_bits` for `a` and `b`.
    /// - is_xor_gate = 0 -> Performs AND between the first `num_bits` for `a` and `b`.
    ///
    /// ## Panics
    /// This function will panic if the num_bits specified is not even `num_bits % 2 != 0`.
    pub(crate) fn logic_gate(
        &mut self,
        a: Variable,
        b: Variable,
        num_bits: usize,
        is_xor_gate: bool,
    ) -> Variable {
        // Since we work on base4, we need to guarantee that we have an even
        // number of bits representing the greatest input.
        assert_eq!(num_bits & 1, 0);
        // We will have exactly `num_bits / 2` quads (quaternary digits) representing
        // both numbers.
        let num_quads = num_bits >> 1;
        // Allocate accumulators for gate construction.
        let mut left_accumulator = Scalar::zero();
        let mut right_accumulator = Scalar::zero();
        let mut out_accumulator = Scalar::zero();
        let mut left_quad: u8;
        let mut right_quad: u8;
        // Get vars as bits and reverse them to get the Little Endian repr.
        let a_bit_iter = BitIterator8::new(self.variables[&a].to_bytes());
        let a_bits: Vec<_> = a_bit_iter.skip(256 - num_bits).collect();
        let b_bit_iter = BitIterator8::new(self.variables[&b].to_bytes());
        let b_bits: Vec<_> = b_bit_iter.skip(256 - num_bits).collect();
        // XXX Doc this
        assert!(a_bits.len() >= num_bits);
        assert!(b_bits.len() >= num_bits);

        // If we take a look to the program memory structure of the ref. impl.
        // * +-----+-----+-----+-----+
        // * |  A  |  B  |  C  |  D  |
        // * +-----+-----+-----+-----+
        // * | 0   | 0   | w1  | 0   |
        // * | a1  | b1  | w2  | c1  |
        // * | a2  | b2  | w3  | c2  |
        // * |  :  |  :  |  :  |  :  |
        // * | an  | bn  | --- | cn  |
        // * +-----+-----+-----+-----+
        // We need to have w_4, w_l and w_r pointing to one gate ahead of w_o.
        // We increase the gate idx and assign w_4, w_l and w_r to `zero`.
        // Now we can add the first row as: `| 0 | 0 | -- | 0 |`.
        // Note that `w_1` will be set on the first loop iteration.
        self.perm
            .add_variable_to_map(self.zero_var, WireData::Left(self.n));
        self.perm
            .add_variable_to_map(self.zero_var, WireData::Right(self.n));
        self.perm
            .add_variable_to_map(self.zero_var, WireData::Fourth(self.n));
        self.w_l.push(self.zero_var);
        self.w_r.push(self.zero_var);
        self.w_4.push(self.zero_var);
        // Increase the gate index so we can add the following rows in the correct order.
        self.n += 1;

        // Start generating accumulator rows and adding them to the circuit.
        // Note that we will do this process exactly `num_bits / 2` counting that
        // the first step above was done correctly to obtain the right format the the first row.
        // This means that we will need to pad the end of the memory program once we've built it.
        // As we can see in the last row structure: `| an  | bn  | --- | cn  |`.
        for i in 0..num_quads {
            // On each round, we will commit every accumulator step. To do so,
            // we first need to get the ith quads of `a` and `b` and then compute
            // `out_quad`(logical OP result) and `prod_quad`(intermediate prod result).

            // Here we compute each quad by taking the most significant bit
            // multiplying it by two and adding to it the less significant
            // bit to form the quad with a ternary value encapsulated in an `u8`
            // in Big Endian form.
            left_quad = {
                let idx = i << 1;
                ((a_bits[idx] as u8) << 1) + (a_bits[idx + 1] as u8)
            };
            right_quad = {
                let idx = i << 1;
                ((b_bits[idx] as u8) << 1) + (b_bits[idx + 1] as u8)
            };
            let left_quad_fr = Scalar::from(left_quad as u64);
            let right_quad_fr = Scalar::from(right_quad as u64);
            // The `out_quad` is the result of the bitwise ops `&` or `^` between
            // the left and right quads. The op is decided with a boolean flag set
            // as input of the function.
            let out_quad_fr = match is_xor_gate {
                true => Scalar::from((left_quad ^ right_quad) as u64),
                false => Scalar::from((left_quad & right_quad) as u64),
            };
            // We also need to allocate a helper item which is the result
            // of the product between the left and right quads.
            // This param is identified as `w` in the program memory and
            // is needed to prevent the degree of our quotient polynomial from blowing up
            let prod_quad_fr = Scalar::from((left_quad * right_quad) as u64);

            // Now that we've computed this round results, we need to apply the
            // logic transition constraint that will check the following:
            // a      - 4 . a  ϵ [0, 1, 2, 3]
            //   i + 1        i
            //
            //
            //
            //
            //  b      - 4 . b  ϵ [0, 1, 2, 3]
            //   i + 1        i
            //
            //
            //
            //
            //                    /                 \          /                 \
            //  c      - 4 . c  = | a      - 4 . a  | (& OR ^) | b      - 4 . b  |
            //   i + 1        i   \  i + 1        i /          \  i + 1        i /
            //
            let prev_left_accum = left_accumulator;
            let prev_right_accum = right_accumulator;
            let prev_out_accum = out_accumulator;
            // We also need to add the computed quad fr_s to the circuit representing a logic gate.
            // To do so, we just mul by 4 the previous accomulated result and we add to it
            // the new computed quad.
            // With this technique we're basically accumulating the quads and adding them to get back to the
            // starting value, at the i-th iteration.
            //          i
            //         ===
            //         \                     j
            //  x   =  /    q            . 4
            //   i     ===   (bits/2 - j)
            //        j = 0
            //
            left_accumulator *= Scalar::from(4u64);
            left_accumulator += left_quad_fr;
            right_accumulator *= Scalar::from(4u64);
            right_accumulator += right_quad_fr;
            out_accumulator *= Scalar::from(4u64);
            out_accumulator += out_quad_fr;
            // Apply logic transition constraints.
            assert!(left_accumulator - (prev_left_accum * Scalar::from(4u64)) < Scalar::from(4u64));
            assert!(
                right_accumulator - (prev_right_accum * Scalar::from(4u64)) < Scalar::from(4u64)
            );
            assert!(out_accumulator - (prev_out_accum * Scalar::from(4u64)) < Scalar::from(4u64));

            // Get variables pointing to the previous accumulated values.
            let var_a = self.add_input(left_accumulator);
            let var_b = self.add_input(right_accumulator);
            // On the last row of the program memory, we need to pad the
            // output wire with a zero since we started to include it's
            // accumulators one gate before the other wire ones.
            let var_c = match i == num_quads {
                true => self.zero_var,
                false => self.add_input(prod_quad_fr),
            };
            let var_4 = self.add_input(out_accumulator);
            // Add the variables to the variable map linking them to it's
            // corresponding gate index.
            //
            // Note that by doing this, we are basically setting the wire_coeffs
            // of the wire polynomials, but we still need to link the selector_poly
            // coefficients in order to be able to have complete gates.
            //
            // Also note that here we're setting left, right and fourth variables to the
            // actual gate, meanwhile we set out to the previous gate.
            self.perm.add_variable_to_map(var_a, WireData::Left(self.n));
            self.perm
                .add_variable_to_map(var_b, WireData::Right(self.n));
            self.perm
                .add_variable_to_map(var_4, WireData::Fourth(self.n));
            self.perm
                .add_variable_to_map(var_c, WireData::Output(self.n - 1));
            // Push the variables to it's actual wire vector storage
            self.w_l.push(var_a);
            self.w_r.push(var_b);
            self.w_o.push(var_c);
            self.w_4.push(var_4);
            // Update the gate index
            self.n += 1;
        }

        // We have one missing value for the last row of the program memory which
        // is `w_o` since the rest of wires are pointing one gate ahead.
        // To fix this, we simply pad with a 0 so the last row of the program memory
        // will look like this:
        // | an  | bn  | --- | cn  |
        self.perm
            .add_variable_to_map(self.zero_var, WireData::Output(self.n - 1));
        self.w_o.push(self.zero_var);

        // Now the wire values are set for each gate, indexed and mapped in the
        // `variable_map` inside of the `Permutation` struct.
        // Now we just need to extend the selector polynomials with the appropiate
        // coefficients to form complete logic gates.
        for _ in 0..num_quads {
            self.q_m.push(Scalar::zero());
            self.q_l.push(Scalar::zero());
            self.q_r.push(Scalar::zero());
            self.q_arith.push(Scalar::zero());
            self.q_o.push(Scalar::zero());
            self.q_4.push(Scalar::zero());
            self.q_range.push(Scalar::zero());
            match is_xor_gate {
                true => {
                    self.q_c.push(-Scalar::one());
                    self.q_logic.push(-Scalar::one());
                }
                false => {
                    self.q_c.push(Scalar::one());
                    self.q_logic.push(Scalar::one());
                }
            };
        }
        // For the last gate, `q_c` and `q_logic` we use no-op values (Zero).
        self.q_m.push(Scalar::zero());
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        self.q_arith.push(Scalar::zero());
        self.q_o.push(Scalar::zero());
        self.q_4.push(Scalar::zero());
        self.q_range.push(Scalar::zero());
        self.q_c.push(Scalar::zero());
        self.q_logic.push(Scalar::zero());

        // We also need to extend the `public_inputs` Vec with
        // zeros since the coeffs will not be added by the user as
        // they are not needed.
        //
        // It makes no sense to allow the user introduce any kind of value
        // in the middle of the logical gate iteration.
        let zeros = vec![Scalar::zero(); num_quads + 1];
        self.public_inputs.extend(zeros.iter());

        // Now we need to assert that the sum of accumulated values
        // matches the original values provided to the fn.
        // Note that we're only considering the quads that are included
        // in the range 0..num_bits. So, when actually executed, we're checking that
        // x & ((1 << num_bits +1) -1) == [0..num_quads] accumulated sums of x.
        //
        // We could also check that the last gates wire coefficients match the
        // original values introduced in the function.
        // This can be done with an `assert_equal` constraint gate or simply
        // by taking the values behind the n'th variables of `w_l` & `w_r` and
        // checking that they're equal to the original ones behind the variables
        // sent through the function parameters.
        assert_eq!(self.variables[&a], self.variables[&self.w_l[self.n - 1]]);
        assert_eq!(self.variables[&b], self.variables[&self.w_r[self.n - 1]]);

        // Once the inputs are checked against the accumulated additions,
        // we can safely return the resulting variable of the gate computation
        // which is stored on the last program memory row and in the column that
        // `w_4` is holding.
        self.w_4[self.w_4.len() - 1]
    }

    /// Adds a logical XOR gate that performs the XOR between two values for the
    /// specified first `num_bits` returning a `Variable` holding the result.
    ///
    /// # Panics
    ///
    /// If the `num_bits` specified in the fn params is odd.
    pub fn logic_xor_gate(&mut self, a: Variable, b: Variable, num_bits: usize) -> Variable {
        self.logic_gate(a, b, num_bits, true)
    }

    /// Adds a logical AND gate that performs the bitwise AND between two values
    /// for the specified first `num_bits` returning a `Variable` holding the result.
    ///
    /// # Panics
    ///
    /// If the `num_bits` specified in the fn params is odd.
    pub fn logic_and_gate(&mut self, a: Variable, b: Variable, num_bits: usize) -> Variable {
        self.logic_gate(a, b, num_bits, false)
    }

    /// XXX: Doc this.
    pub fn scalar_mul(&mut self, scalar: &Fr) -> () {
        // Get the JubJub Scalar in w-3 WNAF form
        // Then work from the most siginificant bit 
        // by flipping the result.
        let mut w_naf_scalar = scalar.compute_windowed_naf(3u8).to_vec();
        w_naf_scalar.reverse();
        // The point Q will be used as the accumulator where the rounds
        // will deposit the result.
        // Q is the output point for (x,y).
        let mut Q = AffinePoint::one();
        // Allocate accumulator variables
        let mut wnaf_accum = Scalar::zero();
        let four = Scalar::from(4u64);

        // We iterate over the w_naf terms.
        for wnaf_term in w_naf_scalar {
            wnaf_accum *= four;
            let wnaf_as_scalar = match (wnaf_term > 0i8, wnaf_term < 0i8, wnaf_term == 0i8) {
                (true, false, false) => Scalar::from(wnaf_term as u64),
                (false, true, false) => Scalar::zero(),
                (false, false, true) => -Scalar::from(wnaf_term.abs() as u64),
                (_, _, _) => unreachable!(),
            };
            // Accumulated wnaf scalar value to be pushed.
            wnaf_accum += wnaf_as_scalar;
            Q = AffinePoint::from(AffinePoint::from(Q).double());

            // Here we need to pick a point from the ODD_BASEPOINT_MULTIPLES_TABLE according to
            // the actual w_naf_term and then add it to Q.
            //
            // Once this is done we need to place each term of points and the accumulator
            // on it's corresponding wire/selector.
        }

        {
            self.w_l.a: Variable
            self.w_r.b: Variable,
            self.w_o.c: Variable,
            self.w_l.d: Variable,
            self.q_l: Scalar,
            self.q_r: Scalar,
            self.q_ecc: Scalar,
            self.q_o: Scalar
        
            self.
        }
    }

    

    

    /// Asserts that two variables are the same
    // XXX: Instead of wasting a gate, we can use the permutation polynomial to do this
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

    /// This function is used to add a blinding factor to the witness polynomials
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
        self.q_logic.push(Scalar::zero());
        self.public_inputs.push(Scalar::zero());
        let var_six = self.add_input(Scalar::from(6));
        let var_one = self.add_input(Scalar::from(1));
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
        self.q_logic.push(Scalar::zero());
        self.public_inputs.push(Scalar::zero());
        self.w_l.push(var_min_twenty);
        self.w_r.push(var_six);
        self.w_o.push(var_seven);
        self.w_4.push(self.zero_var);
        self.perm
            .add_variables_to_map(var_min_twenty, var_six, var_seven, self.zero_var, self.n);
        self.n += 1;
    }

    /// Utility function that allows to check on the "front-end"
    /// side of the PLONK implementation if the identity polynomial
    /// is satisfied for each one of the `StandardComposer`'s gates.
    #[cfg(feature = "trace")]
    pub fn check_circuit_satisfied(&self) {
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
            let qlogic = self.q_logic[i];
            let pi = self.public_inputs[i];

            let a = w_l[i];
            let a_next = w_l[(i + 1) % self.n];
            let b = w_r[i];
            let b_next = w_r[(i + 1) % self.n];
            let c = w_o[i];
            let d = w_4[i];
            let d_next = w_4[(i + 1) % self.n];
            #[cfg(feature = "trace-print")]
            println!(
                "--------------------------------------------\n
            #Gate Index = {}
            #Selector Polynomials:\n
            - qm -> {:?}\n
            - ql -> {:?}\n
            - qr -> {:?}\n
            - q4 -> {:?}\n
            - qo -> {:?}\n
            - qc -> {:?}\n
            - q_arith -> {:?}\n
            - q_range -> {:?}\n
            - q_logic -> {:?}\n
            # Witness polynomials:\n
            - w_l -> {:?}\n
            - w_r -> {:?}\n
            - w_o -> {:?}\n
            - w_4 -> {:?}\n",
                i, qm, ql, qr, q4, qo, qc, qarith, qrange, qlogic, a, b, c, d
            );
            let k = qarith * ((qm * a * b) + (ql * a) + (qr * b) + (qo * c) + (q4 * d) + pi + qc)
                + qlogic
                    * (((delta(a_next - four * a) - delta(b_next - four * b)) * c)
                        + delta(a_next - four * a)
                        + delta(b_next - four * b)
                        + delta(d_next - four * d)
                        + match (qlogic == Scalar::one(), qlogic == -Scalar::one()) {
                            (true, false) => (a & b) - d,
                            (false, true) => (a ^ b) - d,
                            (false, false) => Scalar::zero(),
                            _ => unreachable!(),
                        })
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
    use crate::proof_system::{Prover, Verifier};
    use dusk_bls12_381::Scalar as Fr;

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
        assert!(composer.q_logic.len() == size);
        assert!(composer.w_l.len() == size);
        assert!(composer.w_r.len() == size);
        assert!(composer.w_o.len() == size);
    }

    #[allow(unused_variables)]
    #[test]
    fn test_prove_verify() {
        let res = test_gadget(
            |composer| {
                // do nothing except add the dummy constraints
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_logic_xor_constraint() {
        // Should pass since the XOR result is correct and the bit-num is even.
        let res = test_gadget(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(500u64));
                let witness_b = composer.add_input(Scalar::from(357u64));
                let xor_res = composer.logic_gate(witness_a, witness_b, 10, true);
                // Check that the XOR result is indeed what we are expecting.
                composer.constrain_to_constant(
                    xor_res,
                    Scalar::from(500u64 ^ 357u64),
                    Scalar::zero(),
                );
            },
            200,
        );
        assert!(res.is_ok());

        // Should pass since the AND result is correct even the bit-num is even.
        let res = test_gadget(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(469u64));
                let witness_b = composer.add_input(Scalar::from(321u64));
                let xor_res = composer.logic_gate(witness_a, witness_b, 10, false);
                // Check that the AND result is indeed what we are expecting.
                composer.constrain_to_constant(
                    xor_res,
                    Scalar::from(469u64 & 321u64),
                    Scalar::zero(),
                );
            },
            200,
        );
        assert!(res.is_ok());

        // Should not pass since the XOR result is not correct even the bit-num is even.
        let res = test_gadget(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(139u64));
                let witness_b = composer.add_input(Scalar::from(33u64));
                let xor_res = composer.logic_gate(witness_a, witness_b, 10, true);
                // Check that the XOR result is indeed what we are expecting.
                composer.constrain_to_constant(
                    xor_res,
                    Scalar::from(139u64 & 33u64),
                    Scalar::zero(),
                );
            },
            200,
        );
        assert!(res.is_err());
    }

    #[test]
    #[should_panic]
    fn test_logical_gate_odd_bit_num() {
        // Should fail since the bit-num is odd.
        let _ = test_gadget(
            |composer| {
                let witness_a = composer.add_input(Scalar::from(500u64));
                let witness_b = composer.add_input(Scalar::from(499u64));
                let xor_res = composer.logic_gate(witness_a, witness_b, 9, true);
                // Check that the XOR result is indeed what we are expecting.
                composer.constrain_to_constant(xor_res, Scalar::from(7u64), Scalar::zero());
            },
            200,
        );
    }

    #[test]
    fn test_range_constraint() {
        // Should fail as the number is not 32 bits
        let res = test_gadget(
            |composer| {
                let witness = composer.add_input(Scalar::from((u32::max_value() as u64) + 1));
                composer.range_gate(witness, 32);
            },
            200,
        );
        assert!(res.is_err());

        // Should fail as number is greater than 32 bits
        let res = test_gadget(
            |composer| {
                let witness = composer.add_input(Scalar::from(u64::max_value()));
                composer.range_gate(witness, 32);
            },
            200,
        );
        assert!(res.is_err());

        // Should pass as the number is within 34 bits
        let res = test_gadget(
            |composer| {
                let witness = composer.add_input(Scalar::from(2u64.pow(34) - 1));
                composer.range_gate(witness, 34);
            },
            200,
        );
        assert!(res.is_ok());
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
        let res = test_gadget(
            |composer| {
                let var_one = composer.add_input(Fr::one());

                let should_be_three = composer.big_add(
                    var_one.into(),
                    var_one.into(),
                    composer.zero_var.into(),
                    Scalar::zero(),
                    Scalar::one(),
                );
                composer.constrain_to_constant(should_be_three, Scalar::from(3), Scalar::zero());
                let should_be_four = composer.big_add(
                    var_one.into(),
                    var_one.into(),
                    composer.zero_var.into(),
                    Scalar::zero(),
                    Scalar::from(2),
                );
                composer.constrain_to_constant(should_be_four, Scalar::from(4), Scalar::zero());
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_correct_add_mul_gate() {
        let res = test_gadget(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) = 280
                let four = composer.add_input(Fr::from(4));
                let five = composer.add_input(Fr::from(5));
                let six = composer.add_input(Fr::from(6));
                let seven = composer.add_input(Fr::from(7));

                let fourteen = composer.big_add(
                    four.into(),
                    five.into(),
                    five.into(),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let twenty = composer.big_add(
                    six.into(),
                    seven.into(),
                    seven.into(),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                // There are quite a few ways to check the equation is correct, depending on your circumstance
                // If we already have the output wire, we can constrain the output of the mul_gate to be equal to it
                // If we do not, we can compute it using the `mul`
                // If the output is public, we can also constrain the output wire of the mul gate to it. This is what this test does
                let output = composer.mul(
                    Scalar::one(),
                    fourteen,
                    twenty,
                    Scalar::zero(),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(output, Scalar::from(280), Scalar::zero());
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_correct_add_gate() {
        let res = test_gadget(
            |composer| {
                let zero = composer.add_input(Fr::zero());
                let one = composer.add_input(Fr::one());

                let c = composer.add(
                    (Scalar::one(), one),
                    (Scalar::zero(), zero),
                    Scalar::from(2u64),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(c, Scalar::from(3), Scalar::zero());
            },
            32,
        );
        assert!(res.is_ok())
    }
    #[test]
    fn test_correct_big_add_mul_gate() {
        let res = test_gadget(
            |composer| {
                // Verify that (4+5+5) * (6+7+7) + (8*9) = 352
                let four = composer.add_input(Fr::from(4));
                let five = composer.add_input(Fr::from(5));
                let six = composer.add_input(Fr::from(6));
                let seven = composer.add_input(Fr::from(7));
                let nine = composer.add_input(Fr::from(9));

                let fourteen = composer.big_add(
                    four.into(),
                    five.into(),
                    five.into(),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let twenty = composer.big_add(
                    six.into(),
                    seven.into(),
                    seven.into(),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let output = composer.big_mul(
                    Scalar::one(),
                    fourteen,
                    twenty,
                    (Scalar::from(8), nine),
                    Scalar::zero(),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(output, Scalar::from(352), Scalar::zero());
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_incorrect_add_mul_gate() {
        let res = test_gadget(
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
                    Scalar::zero(),
                );

                let six_plus_seven = composer.big_add(
                    six.into(),
                    seven.into(),
                    composer.zero_var.into(),
                    Scalar::zero(),
                    Scalar::zero(),
                );

                let output = composer.mul(
                    Scalar::one(),
                    five_plus_five,
                    six_plus_seven,
                    Scalar::zero(),
                    Scalar::zero(),
                );
                composer.constrain_to_constant(output, Scalar::from(117), Scalar::zero());
            },
            200,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_correct_bool_gate() {
        let res = test_gadget(
            |composer| {
                let zero = composer.add_input(Fr::zero());
                let one = composer.add_input(Fr::one());

                composer.bool_gate(zero);
                composer.bool_gate(one);
            },
            32,
        );
        assert!(res.is_ok())
    }

    #[test]
    fn test_incorrect_bool_gate() {
        let res = test_gadget(
            |composer| {
                let zero = composer.add_input(Fr::from(5));
                let one = composer.add_input(Fr::one());

                composer.bool_gate(zero);
                composer.bool_gate(one);
            },
            32,
        );
        assert!(res.is_err())
    }

    fn dummy_gadget(n: usize, composer: &mut StandardComposer) {
        let one = Scalar::one();

        let var_one = composer.add_input(one);

        for _ in 0..n {
            composer.big_add(
                var_one.into(),
                var_one.into(),
                composer.zero_var.into(),
                Scalar::zero(),
                Scalar::zero(),
            );
        }

        composer.add_dummy_constraints();
    }

    fn test_gadget(gadget: fn(composer: &mut StandardComposer), n: usize) -> Result<(), Error> {
        // Common View
        let public_parameters = PublicParameters::setup(2 * n, &mut rand::thread_rng())?;
        // Provers View
        let (proof, public_inputs) = {
            // Create a prover struct
            let mut prover = Prover::new(b"demo");

            // Additionally key the transcript
            prover.key_transcript(b"key", b"additional seed information");

            // Add gadgets
            dummy_gadget(7, prover.mut_cs());
            gadget(&mut prover.mut_cs());

            // Commit Key
            let (ck, _) =
                public_parameters.trim(2 * prover.cs.circuit_size().next_power_of_two())?;

            // Preprocess circuit
            prover.preprocess(&ck)?;

            // Once the prove method is called, the public inputs are cleared
            // So pre-fetch these before calling Prove
            let public_inputs = prover.cs.public_inputs.clone();

            // Compute Proof
            (prover.prove(&ck)?, public_inputs)
        };
        // Verifiers view
        //
        // Create a Verifier object
        let mut verifier = Verifier::new(b"demo");

        // Additionally key the transcript
        verifier.key_transcript(b"key", b"additional seed information");

        // Add gadgets
        dummy_gadget(7, verifier.mut_cs());
        gadget(&mut verifier.mut_cs());

        // Compute Commit and Verifier Key
        let (ck, vk) = public_parameters.trim(verifier.cs.circuit_size().next_power_of_two())?;

        // Preprocess circuit
        verifier.preprocess(&ck)?;

        // Verify proof
        verifier.verify(&proof, &vk, &public_inputs)
    }

    #[test]
    fn test_multiple_proofs() {
        let public_parameters = PublicParameters::setup(2 * 30, &mut rand::thread_rng()).unwrap();

        // Create a prover struct
        let mut prover = Prover::new(b"demo");

        // Add gadgets
        dummy_gadget(10, prover.mut_cs());

        // Commit Key
        let (ck, _) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        let public_inputs = prover.cs.public_inputs.clone();

        let mut proofs = Vec::new();

        // Compute multiple proofs
        for _ in 0..10 {
            proofs.push(prover.prove(&ck).unwrap());

            // Add another witness instance
            dummy_gadget(10, prover.mut_cs());
        }

        // Verifier
        //
        let mut verifier = Verifier::new(b"demo");

        // Add gadgets
        dummy_gadget(10, verifier.mut_cs());

        // Commit and Verifier Key
        let (ck, vk) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess
        verifier.preprocess(&ck).unwrap();

        for proof in proofs {
            let ok = verifier.verify(&proof, &vk, &public_inputs);
            assert!(ok.is_ok());
        }
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
                Scalar::zero(),
            );
        }

        // Circuit size is n+1 because we have an extra gate which forces the first witness to be zero
        assert_eq!(n + 1, composer.circuit_size())
    }
}
