// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The `Composer` is a Trait that is actually defining some kind of
//! Circuit Builder for PLONK.
//!
//! In that sense, here we have the implementation of the `StandardComposer`
//! which has been designed in order to provide the maximum amount of
//! performance while having a big scope in utility terms.
//!
//! It allows us not only to build Add and Mul constraints but also to build
//! ECC op. gates, Range checks, Logical gates (Bitwise ops) etc.

// Gate fn's have a large number of attributes but
// it is intended to be like this in order to provide
// maximum performance and minimum circuit sizes.
#![allow(clippy::too_many_arguments)]

use crate::constraint_system::Variable;
use crate::permutation::Permutation;
use alloc::collections::BTreeMap;
use dusk_bls12_381::BlsScalar;
use hashbrown::HashMap;

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
    pub(crate) q_m: Vec<BlsScalar>,
    // Left wire selector
    pub(crate) q_l: Vec<BlsScalar>,
    // Right wire selector
    pub(crate) q_r: Vec<BlsScalar>,
    // Output wire selector
    pub(crate) q_o: Vec<BlsScalar>,
    // Fourth wire selector
    pub(crate) q_4: Vec<BlsScalar>,
    // Constant wire selector
    pub(crate) q_c: Vec<BlsScalar>,
    // Arithmetic wire selector
    pub(crate) q_arith: Vec<BlsScalar>,
    // Range selector
    pub(crate) q_range: Vec<BlsScalar>,
    // Logic selector
    pub(crate) q_logic: Vec<BlsScalar>,
    // Fixed base group addition selector
    pub(crate) q_fixed_group_add: Vec<BlsScalar>,
    // Variable base group addition selector
    pub(crate) q_variable_group_add: Vec<BlsScalar>,

    /// Sparse representation of the Public Inputs linking the positions of the
    /// non-zero ones to it's actual values.
    pub(crate) public_inputs_sparse_store: BTreeMap<usize, BlsScalar>,

    // Witness vectors
    pub(crate) w_l: Vec<Variable>,
    pub(crate) w_r: Vec<Variable>,
    pub(crate) w_o: Vec<Variable>,
    pub(crate) w_4: Vec<Variable>,

    /// A zero variable that is a part of the circuit description.
    /// We reserve a variable to be zero in the system
    /// This is so that when a gate only uses three wires, we set the fourth
    /// wire to be the variable that references zero
    pub(crate) zero_var: Variable,

    // These are the actual variable values
    // N.B. They should not be exposed to the end user once added into the
    // composer
    pub(crate) variables: HashMap<Variable, BlsScalar>,

    pub(crate) perm: Permutation,
}

impl StandardComposer {
    /// Returns the number of gates in the circuit
    pub fn circuit_size(&self) -> usize {
        self.n
    }

    /// Constructs a dense vector of the Public Inputs from the positions and
    /// the sparse vector that contains the values.
    pub fn construct_dense_pi_vec(&self) -> Vec<BlsScalar> {
        let mut pi = vec![BlsScalar::zero(); self.n];
        self.public_inputs_sparse_store
            .iter()
            .for_each(|(pos, value)| {
                pi[*pos] = *value;
            });
        pi
    }

    /// Returns the positions that the Public Inputs occupy in this Composer
    /// instance.
    // TODO: Find a more performant solution which can return a ref to a Vec or
    // Iterator.
    pub fn pi_positions(&self) -> Vec<usize> {
        self.public_inputs_sparse_store
            .keys()
            .copied()
            .collect::<Vec<usize>>()
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
    pub fn add_witness_to_circuit_description(
        &mut self,
        value: BlsScalar,
    ) -> Variable {
        let var = self.add_input(value);
        self.constrain_to_constant(var, value, None);
        var
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
            q_fixed_group_add: Vec::with_capacity(expected_size),
            q_variable_group_add: Vec::with_capacity(expected_size),
            public_inputs_sparse_store: BTreeMap::new(),

            w_l: Vec::with_capacity(expected_size),
            w_r: Vec::with_capacity(expected_size),
            w_o: Vec::with_capacity(expected_size),
            w_4: Vec::with_capacity(expected_size),

            zero_var: Variable(0),

            variables: HashMap::with_capacity(expected_size),

            perm: Permutation::new(),
        };

        // Reserve the first variable to be zero
        composer.zero_var =
            composer.add_witness_to_circuit_description(BlsScalar::zero());

        // Add dummy constraints
        composer.add_dummy_constraints();

        composer
    }

    /// Add Input first calls the `Permutation` struct
    /// to generate and allocate a new variable `var`.
    /// The composer then links the Variable to the BlsScalar
    /// and returns the Variable for use in the system.
    pub fn add_input(&mut self, s: BlsScalar) -> Variable {
        // Get a new Variable from the permutation
        let var = self.perm.new_variable();
        // The composer now links the BlsScalar to the Variable returned from
        // the Permutation
        self.variables.insert(var, s);

        var
    }

    /// Adds a width-3 poly gate.
    /// This gate gives total freedom to the end user to implement the
    /// corresponding circuits in the most optimized way possible because
    /// the under has access to the whole set of variables, as well as
    /// selector coefficients that take part in the computation of the gate
    /// equation.
    ///
    /// The final constraint added will force the following:
    /// `(a * b) * q_m + a * q_l + b * q_r + q_c + PI + q_o * c = 0`.
    pub fn poly_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_m: BlsScalar,
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_o: BlsScalar,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
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
        self.q_4.push(BlsScalar::zero());
        self.q_arith.push(BlsScalar::one());

        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());

        if let Some(pi) = pi {
            assert!(self
                .public_inputs_sparse_store
                .insert(self.n, pi)
                .is_none());
        }

        self.perm
            .add_variables_to_map(a, b, c, self.zero_var, self.n);
        self.n += 1;

        (a, b, c)
    }

    /// Adds a gate which is designed to constrain a `Variable` to have
    /// a specific constant value which is sent as a `BlsScalar`.
    pub fn constrain_to_constant(
        &mut self,
        a: Variable,
        constant: BlsScalar,
        pi: Option<BlsScalar>,
    ) {
        self.poly_gate(
            a,
            a,
            a,
            BlsScalar::zero(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            -constant,
            pi,
        );
    }

    /// Asserts that two variables are the same
    // XXX: Instead of wasting a gate, we can use the permutation polynomial to
    // do this
    pub fn assert_equal(&mut self, a: Variable, b: Variable) {
        self.poly_gate(
            a,
            b,
            self.zero_var,
            BlsScalar::zero(),
            BlsScalar::one(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );
    }

    /// Conditionally selects a Variable based on an input bit
    /// If:
    ///     bit == 1 => choice_a,
    ///     bit == 0 => choice_b,
    pub fn conditional_select(
        &mut self,
        bit: Variable,
        choice_a: Variable,
        choice_b: Variable,
    ) -> Variable {
        // bit * choice_a
        let bit_times_a =
            self.mul(BlsScalar::one(), bit, choice_a, BlsScalar::zero(), None);

        // 1 - bit
        let one_min_bit = self.add(
            (-BlsScalar::one(), bit),
            (BlsScalar::zero(), self.zero_var),
            BlsScalar::one(),
            None,
        );

        // (1 - bit) * b
        let one_min_bit_choice_b = self.mul(
            BlsScalar::one(),
            one_min_bit,
            choice_b,
            BlsScalar::zero(),
            None,
        );

        // [ (1 - bit) * b ] + [ bit * a ]
        self.add(
            (BlsScalar::one(), one_min_bit_choice_b),
            (BlsScalar::one(), bit_times_a),
            BlsScalar::zero(),
            None,
        )
    }

    /// This function is used to add a blinding factor to the witness
    /// polynomials XXX: Split this into two separate functions and document
    /// XXX: We could add another section to add random witness variables, with
    /// selector polynomials all zero
    pub fn add_dummy_constraints(&mut self) {
        // Add a dummy constraint so that we do not have zero polynomials
        self.q_m.push(BlsScalar::from(1));
        self.q_l.push(BlsScalar::from(2));
        self.q_r.push(BlsScalar::from(3));
        self.q_o.push(BlsScalar::from(4));
        self.q_c.push(BlsScalar::from(4));
        self.q_4.push(BlsScalar::one());
        self.q_arith.push(BlsScalar::one());
        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());
        let var_six = self.add_input(BlsScalar::from(6));
        let var_one = self.add_input(BlsScalar::from(1));
        let var_seven = self.add_input(BlsScalar::from(7));
        let var_min_twenty = self.add_input(-BlsScalar::from(20));
        self.w_l.push(var_six);
        self.w_r.push(var_seven);
        self.w_o.push(var_min_twenty);
        self.w_4.push(var_one);
        self.perm.add_variables_to_map(
            var_six,
            var_seven,
            var_min_twenty,
            var_one,
            self.n,
        );
        self.n += 1;
        //Add another dummy constraint so that we do not get the identity
        // permutation
        self.q_m.push(BlsScalar::from(1));
        self.q_l.push(BlsScalar::from(1));
        self.q_r.push(BlsScalar::from(1));
        self.q_o.push(BlsScalar::from(1));
        self.q_c.push(BlsScalar::from(127));
        self.q_4.push(BlsScalar::zero());
        self.q_arith.push(BlsScalar::one());
        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());
        self.w_l.push(var_min_twenty);
        self.w_r.push(var_six);
        self.w_o.push(var_seven);
        self.w_4.push(self.zero_var);
        self.perm.add_variables_to_map(
            var_min_twenty,
            var_six,
            var_seven,
            self.zero_var,
            self.n,
        );
        self.n += 1;
    }

    /// Utility function that allows to check on the "front-end"
    /// side of the PLONK implementation if the identity polynomial
    /// is satisfied for each one of the `StandardComposer`'s gates.
    /// XXX: This is messy and will be removed in a later PR.
    #[cfg(feature = "trace")]
    pub fn check_circuit_satisfied(&self) {
        let w_l: Vec<&BlsScalar> = self
            .w_l
            .iter()
            .map(|w_l_i| self.variables.get(&w_l_i).unwrap())
            .collect();
        let w_r: Vec<&BlsScalar> = self
            .w_r
            .iter()
            .map(|w_r_i| self.variables.get(&w_r_i).unwrap())
            .collect();
        let w_o: Vec<&BlsScalar> = self
            .w_o
            .iter()
            .map(|w_o_i| self.variables.get(&w_o_i).unwrap())
            .collect();
        let w_4: Vec<&BlsScalar> = self
            .w_4
            .iter()
            .map(|w_4_i| self.variables.get(&w_4_i).unwrap())
            .collect();
        // Computes f(f-1)(f-2)(f-3)
        let delta = |f: BlsScalar| -> BlsScalar {
            let f_1 = f - BlsScalar::one();
            let f_2 = f - BlsScalar::from(2);
            let f_3 = f - BlsScalar::from(3);
            f * f_1 * f_2 * f_3
        };
        let pi_vec = self.construct_dense_pi_vec();
        let four = BlsScalar::from(4);
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
            let qfixed = self.q_fixed_group_add[i];
            let qvar = self.q_variable_group_add[i];
            let pi = pi_vec[i];

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
            - q_fixed_group_add -> {:?}\n
            - q_variable_group_add -> {:?}\n
            # Witness polynomials:\n
            - w_l -> {:?}\n
            - w_r -> {:?}\n
            - w_o -> {:?}\n
            - w_4 -> {:?}\n",
                i,
                qm,
                ql,
                qr,
                q4,
                qo,
                qc,
                qarith,
                qrange,
                qlogic,
                qfixed,
                qvar,
                a,
                b,
                c,
                d
            );
            let k = qarith
                * ((qm * a * b)
                    + (ql * a)
                    + (qr * b)
                    + (qo * c)
                    + (q4 * d)
                    + pi
                    + qc)
                + qlogic
                    * (((delta(a_next - four * a) - delta(b_next - four * b))
                        * c)
                        + delta(a_next - four * a)
                        + delta(b_next - four * b)
                        + delta(d_next - four * d)
                        + match (
                            qlogic == BlsScalar::one(),
                            qlogic == -BlsScalar::one(),
                        ) {
                            (true, false) => (a & b) - d,
                            (false, true) => (a ^ b) - d,
                            (false, false) => BlsScalar::zero(),
                            _ => unreachable!(),
                        })
                + qrange
                    * (delta(c - four * d)
                        + delta(b - four * c)
                        + delta(a - four * b)
                        + delta(d_next - four * a));

            assert_eq!(k, BlsScalar::zero(), "Check failed at gate {}", i,);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use super::*;
    use crate::commitment_scheme::kzg10::PublicParameters;
    use crate::proof_system::{Prover, Verifier};
    use rand_core::OsRng;

    #[test]
    /// Tests that a circuit initially has 3 gates
    fn test_initial_circuit_size() {
        let composer: StandardComposer = StandardComposer::new();
        // Circuit size is n+3 because
        // - We have an extra gate which forces the first witness to be zero.
        //   This is used when the advice wire is not being used.
        // - We have two gates which ensure that the permutation polynomial is
        //   not the identity and
        // - Another gate which ensures that the selector polynomials are not
        //   all zeroes
        assert_eq!(3, composer.circuit_size())
    }

    #[allow(unused_variables)]
    #[test]
    #[ignore]
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

    #[test]
    fn test_conditional_select() {
        let res = gadget_tester(
            |composer| {
                let bit_1 = composer.add_input(BlsScalar::one());
                let bit_0 = composer.add_input(BlsScalar::zero());

                let choice_a = composer.add_input(BlsScalar::from(10u64));
                let choice_b = composer.add_input(BlsScalar::from(20u64));

                let choice =
                    composer.conditional_select(bit_1, choice_a, choice_b);
                composer.assert_equal(choice, choice_a);

                let choice =
                    composer.conditional_select(bit_0, choice_a, choice_b);
                composer.assert_equal(choice, choice_b);
            },
            32,
        );
        assert!(res.is_ok());
    }

    #[test]
    // XXX: Move this to integration tests
    fn test_multiple_proofs() {
        let public_parameters =
            PublicParameters::setup(2 * 30, &mut OsRng).unwrap();

        // Create a prover struct
        let mut prover = Prover::new(b"demo");

        // Add gadgets
        dummy_gadget(10, prover.mut_cs());

        // Commit Key
        let (ck, _) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        let public_inputs = prover.cs.construct_dense_pi_vec();

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
