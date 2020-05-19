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
use crate::commitment_scheme::kzg10::CommitKey;

use crate::constraint_system::Variable;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::permutation::Permutation;
use crate::proof_system::{widget, PreProcessedCircuit};
use dusk_bls12_381::Scalar;
use failure::Error;
use merlin::Transcript;
use std::collections::HashMap;

/// A composer is a circuit builder
/// and will dictate how a circuit is built
/// We will have a default Composer called `StandardComposer`
#[derive(Debug)]
pub struct StandardComposer {
    // n represents the number of arithmetic gates in the circuit
    pub(crate) n: usize,

    // Selector vectors
    //
    // Multiplier selector
    pub(crate) q_m: Vec<Scalar>,
    // Left wire selector
    pub(crate) q_l: Vec<Scalar>,
    // Right wire selector
    pub(crate) q_r: Vec<Scalar>,
    // output wire selector
    pub(crate) q_o: Vec<Scalar>,
    // fourth wire selector
    pub(crate) q_4: Vec<Scalar>,
    // constant wire selector
    pub(crate) q_c: Vec<Scalar>,
    // arithmetic wire selector
    pub(crate) q_arith: Vec<Scalar>,
    // range selector
    pub(crate) q_range: Vec<Scalar>,
    // logic selector
    pub(crate) q_logic: Vec<Scalar>,

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
    pub(crate) zero_var: Variable,

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
        // Check that the length of the wires is consistent.
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

        // Prover Key for arithmetic circuits
        let arithmetic_prover_key = widget::arithmetic::ProverKey {
            q_m: (q_m_poly, q_m_eval_4n),
            q_l: (q_l_poly, q_l_eval_4n),
            q_r: (q_r_poly, q_r_eval_4n),
            q_o: (q_o_poly, q_o_eval_4n),
            q_c: (q_c_poly.clone(), q_c_eval_4n.clone()),
            q_4: (q_4_poly, q_4_eval_4n),
            q_arith: (q_arith_poly, q_arith_eval_4n),
        };
        // Verifier Key for arithmetic circuits
        let arithmetic_verifier_key = widget::arithmetic::VerifierKey {
            q_m: q_m_poly_commit,
            q_l: q_l_poly_commit,
            q_r: q_r_poly_commit,
            q_o: q_o_poly_commit,
            q_c: q_c_poly_commit,
            q_4: q_4_poly_commit,
            q_arith: q_arith_poly_commit,
        };

        // Prover Key for range circuits
        let range_prover_key = widget::range::ProverKey {
            q_range: (q_range_poly, q_range_eval_4n),
        };
        // Verifier Key for range circuits
        let range_verifier_key = widget::range::VerifierKey {
            q_range: q_range_poly_commit,
        };

        // Prover Key for logic circuits
        let logic_prover_key = widget::logic::ProverKey {
            q_c: (q_c_poly, q_c_eval_4n),
            q_logic: (q_logic_poly, q_logic_eval_4n),
        };
        // Verifier Key for logic circuits
        let logic_verifier_key = widget::logic::VerifierKey {
            q_c: q_c_poly_commit,
            q_logic: q_logic_poly_commit,
        };

        // Prover Key for permutation argument
        let permutation_prover_key = widget::permutation::ProverKey {
            left_sigma: (left_sigma_poly, left_sigma_eval_4n),
            right_sigma: (right_sigma_poly, right_sigma_eval_4n),
            out_sigma: (out_sigma_poly, out_sigma_eval_4n),
            fourth_sigma: (fourth_sigma_poly, fourth_sigma_eval_4n),
            linear_evaluations: linear_eval_4n,
        };
        // Verifier Key for permutation argument
        let permutation_verifier_key = widget::permutation::VerifierKey {
            left_sigma: left_sigma_poly_commit,
            right_sigma: right_sigma_poly_commit,
            out_sigma: out_sigma_poly_commit,
            fourth_sigma: fourth_sigma_poly_commit,
        };

        let ppc = PreProcessedCircuit {
            n: self.n,
            prover_key: widget::ProverKey {
                arithmetic: arithmetic_prover_key,
                logic: logic_prover_key,
                range: range_prover_key,
                permutation: permutation_prover_key,
                // Compute 4n evaluations for X^n -1
                v_h_coset_4n: domain_4n.compute_vanishing_poly_over_coset(domain.size() as u64),
            },
            verifier_key: widget::VerifierKey {
                arithmetic: arithmetic_verifier_key,
                logic: logic_verifier_key,
                range: range_verifier_key,
                permutation: permutation_verifier_key,
            },
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
    /// since the `Vec`s will already have an appropriate allocation at the
    /// beginning of the composing stage.
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

        // Add dummy constraints
        composer.add_dummy_constraints();

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
    /// XXX: Split this into two separate functions and document
    /// XXX: We could add another section to add random witness variables, with selector polynomials all zero
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
    /// XXX: This is messy and will be removed in a later PR.
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
    use super::super::arithmetic;
    use super::super::helper::*;
    use super::*;
    use crate::commitment_scheme::kzg10::PublicParameters;
    use crate::proof_system::{Prover, Verifier};

    #[test]
    /// Tests that the circuit gets padded to the correct length
    /// XXX: We can do this test without dummy_gadget method
    fn test_pad() {
        let mut composer: StandardComposer = StandardComposer::new();
        dummy_gadget(100, &mut composer);

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

    #[test]
    /// Tests that a circuit initially has 3 gates
    fn test_initial_circuit_size() {
        let composer: StandardComposer = StandardComposer::new();
        // Circuit size is n+3 because
        // - We have an extra gate which forces the first witness to be zero. This is used when the advice wire is not being used.
        // - We have two gates which ensure that the permutation polynomial is not the identity and
        // Another gate which ensures that the selector polynomials are not all zeroes
        assert_eq!(3, composer.circuit_size())
    }

    #[allow(unused_variables)]
    #[test]
    /// Tests that an empty circuit proof passes
    fn test_prove_verify() {
        let res = gadget_tester(
            |composer| {
                // do nothing except add the dummy constraints
            },
            200,
        );
        assert!(res.is_ok());
    }

    fn dummy_gadget(n: usize, composer: &mut StandardComposer) {
        let one = Scalar::one();

        let var_one = composer.add_input(one);

        for _ in 0..n {
            arithmetic::big_add(
                composer,
                var_one.into(),
                var_one.into(),
                None,
                Scalar::zero(),
                Scalar::zero(),
            );
        }
    }

    #[test]
    // XXX: Move this to integration tests
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
        for _ in 0..3 {
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
            assert!(verifier.verify(&proof, &vk, &public_inputs).is_ok());
        }
    }
}
