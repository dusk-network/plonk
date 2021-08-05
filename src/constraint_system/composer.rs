// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A `Composer` could be understood as some sort of Trait that is actually
//! defining some kind of Circuit Builder for PLONK.
//!
//! In that sense, here we have the implementation of the [`StandardComposer`]
//! which has been designed in order to provide the maximum amount of
//! performance while having a big scope in utility terms.
//!
//! It allows us not only to build Add and Mul constraints but also to build
//! ECC op. gates, Range checks, Logical gates (Bitwise ops) etc.

// Gate fn's have a large number of attributes but
// it is intended to be like this in order to provide
// maximum performance and minimum circuit sizes.

use crate::constraint_system::Variable;
use crate::error::Error;
use crate::permutation::Permutation;
use crate::plookup::PlookupTable4Arity;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use hashbrown::HashMap;

/// The StandardComposer is the circuit-builder tool that the `dusk-plonk`
/// repository provides so that circuit descriptions can be written, stored and
/// transformed into a [`Proof`](crate::proof_system::Proof) at some point.
///
/// A StandardComposer stores all of the circuit information, being this one
/// all of the witness and circuit descriptors info (values, positions in the
/// circuits, gates and Wires that occupy..), the public inputs, the connection
/// relationships between the witnesses and how they're repesented as Wires (so
/// basically the Permutation argument etc..).
///
/// The StandardComposer also grants us a way to introduce our secret
/// witnesses in a for of a [`Variable`] into the circuit description as well as
/// the public inputs. We can do this with methods like
/// [`StandardComposer::add_input`].
///
/// The StandardComposer also contains as associated functions all the
/// neccessary tools to be able to istrument the circuits that the user needs
/// through the addition of gates. There are functions that may add a single
/// gate to the circuit as for example [`StandardComposer::add_gate`] and others
/// that can add several gates to the circuit description such as
/// [`StandardComposer::conditional_select`].
///
/// Each gate or group of gates adds an specific functionallity or operation to
/// de circuit description, and so, that's why we can understand
/// the StandardComposer as a builder.
#[derive(Debug)]
pub struct StandardComposer {
    /// Number of arithmetic gates in the circuit
    pub(crate) n: usize,

    // Selector vectors
    /// Multiplier selector
    pub(crate) q_m: Vec<BlsScalar>,
    /// Left wire selector
    pub(crate) q_l: Vec<BlsScalar>,
    /// Right wire selector
    pub(crate) q_r: Vec<BlsScalar>,
    /// Output wire selector
    pub(crate) q_o: Vec<BlsScalar>,
    /// Fourth wire selector
    pub(crate) q_4: Vec<BlsScalar>,
    /// Constant wire selector
    pub(crate) q_c: Vec<BlsScalar>,
    /// Arithmetic wire selector
    pub(crate) q_arith: Vec<BlsScalar>,
    /// Range selector
    pub(crate) q_range: Vec<BlsScalar>,
    /// Logic selector
    pub(crate) q_logic: Vec<BlsScalar>,
    /// Fixed base group addition selector
    pub(crate) q_fixed_group_add: Vec<BlsScalar>,
    /// Variable base group addition selector
    pub(crate) q_variable_group_add: Vec<BlsScalar>,
    // Plookup gate wire selector
    pub(crate) q_lookup: Vec<BlsScalar>,

    /// Sparse representation of the Public Inputs linking the positions of the
    /// non-zero ones to it's actual values.
    pub(crate) public_inputs_sparse_store: BTreeMap<usize, BlsScalar>,

    // Witness vectors
    /// Left wire witness vector.
    pub(crate) w_l: Vec<Variable>,
    /// Right wire witness vector.
    pub(crate) w_r: Vec<Variable>,
    /// Output wire witness vector.
    pub(crate) w_o: Vec<Variable>,
    /// Fourth wire witness vector.
    pub(crate) w_4: Vec<Variable>,

    /// Public lookup table
    pub lookup_table: PlookupTable4Arity,

    /// A zero variable that is a part of the circuit description.
    /// We reserve a variable to be zero in the system
    /// This is so that when a gate only uses three wires, we set the fourth
    /// wire to be the variable that references zero
    pub(crate) zero_var: Variable,

    /// These are the actual variable values.
    pub(crate) variables: HashMap<Variable, BlsScalar>,

    /// Permutation argument.
    pub(crate) perm: Permutation,
}

impl StandardComposer {
    /// Returns the number of gates in the circuit
    pub fn circuit_size(&self) -> usize {
        self.n
    }

    /// Returns the total size of the circuit including lookup table rows
    pub fn total_size(&self) -> usize {
        core::cmp::max(self.n, self.lookup_table.0.len())
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
    /// # Note
    ///
    /// The usage of this may cause lots of re-allocations since the `Composer`
    /// holds `Vec` for every polynomial, and these will need to be re-allocated
    /// each time the circuit grows considerably.
    pub fn new() -> Self {
        StandardComposer::with_expected_size(0)
    }

    /// Fixes a [`Variable`] in the witness to be a part of the circuit
    /// description.
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
            q_lookup: Vec::with_capacity(expected_size),
            public_inputs_sparse_store: BTreeMap::new(),

            w_l: Vec::with_capacity(expected_size),
            w_r: Vec::with_capacity(expected_size),
            w_o: Vec::with_capacity(expected_size),
            w_4: Vec::with_capacity(expected_size),

            lookup_table: PlookupTable4Arity::new(),

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

    /// Witness representation of zero of the first variable of any circuit
    pub const fn zero_var(&self) -> Variable {
        self.zero_var
    }

    /// Add Input first calls the Permutation
    /// to generate and allocate a new [`Variable`] `var`.
    ///
    /// The Composer then links the variable to the [`BlsScalar`]
    /// and returns it for its use in the system.
    pub fn add_input(&mut self, s: BlsScalar) -> Variable {
        // Get a new Variable from the permutation
        let var = self.perm.new_variable();
        // The composer now links the BlsScalar to the Variable returned from
        // the Permutation
        self.variables.insert(var, s);

        var
    }

    /// This pushes the result of a lookup read to a gate
    pub fn lookup_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
    ) -> Result<(), Error> {
        self.w_l.push(a);
        self.w_l.push(b);
        self.w_l.push(c);
        self.w_4.push(self.zero_var);
        self.q_l.push(BlsScalar::zero());
        self.q_r.push(BlsScalar::zero());

        // Add selector vectors
        self.q_m.push(BlsScalar::zero());
        self.q_o.push(BlsScalar::zero());
        self.q_c.push(BlsScalar::zero());
        self.q_4.push(BlsScalar::zero());
        self.q_arith.push(BlsScalar::zero());

        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());
        self.q_lookup.push(BlsScalar::one());

        Ok(())
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
        self.q_lookup.push(BlsScalar::zero());

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

    /// Constrain a [`Variable`] to be equal to
    /// a specific constant value which is part of the circuit description and
    /// **NOT** a Public Input. ie. this value will be the same for all of the
    /// circuit instances and [`Proof`](crate::proof_system::Proof)s generated.
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

    /// Add a constraint into the circuit description that states that two
    /// [`Variable`]s are equal.
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

    /// Conditionally selects a [`Variable`] based on an input bit.
    ///
    /// If:
    /// bit == 1 => choice_a,
    /// bit == 0 => choice_b,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Variable`] should had previously
    /// been constrained to be either 1 or 0 using a bool constrain. See:
    /// [`StandardComposer::boolean_gate`].
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

    /// Adds the polynomial f(x) = x * a to the circuit description where
    /// `x = bit`. If:
    /// bit == 1 => value,
    /// bit == 0 => 0,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Variable`] should had previously
    /// been constrained to be either 1 or 0 using a bool constrain. See:
    /// [`StandardComposer::boolean_gate`].
    pub fn conditional_select_zero(
        &mut self,
        bit: Variable,
        value: Variable,
    ) -> Variable {
        // returns bit * value
        self.mul(BlsScalar::one(), bit, value, BlsScalar::zero(), None)
    }

    /// Adds the polynomial f(x) = 1 - x + xa to the circuit description where
    /// `x = bit`. If:
    /// bit == 1 => value,
    /// bit == 0 => 1,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Variable`] should had previously
    /// been constrained to be either 1 or 0 using a bool constrain. See:
    /// [`StandardComposer::boolean_gate`].
    pub fn conditional_select_one(
        &mut self,
        bit: Variable,
        value: Variable,
    ) -> Variable {
        let value_scalar = self.variables.get(&value).unwrap();
        let bit_scalar = self.variables.get(&bit).unwrap();

        let f_x_scalar =
            BlsScalar::one() - bit_scalar + (bit_scalar * value_scalar);
        let f_x = self.add_input(f_x_scalar);

        self.poly_gate(
            bit,
            value,
            f_x,
            BlsScalar::one(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            BlsScalar::one(),
            None,
        );

        f_x
    }

    /// This function is used to add a blinding factor to the witness
    /// polynomials. It essentially adds two dummy gates to the circuit
    /// description which are guaranteed to always satisfy the gate equation.
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
        self.q_lookup.push(BlsScalar::one());
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
        self.q_lookup.push(BlsScalar::one());
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

        // Add dummy rows to lookup table
        // Notice two rows here match dummy wire values above
        self.lookup_table.0.insert(
            0,
            [
                BlsScalar::from(6),
                BlsScalar::from(7),
                -BlsScalar::from(20),
                BlsScalar::from(1),
            ],
        );

        self.lookup_table.0.insert(
            0,
            [
                -BlsScalar::from(20),
                BlsScalar::from(6),
                BlsScalar::from(7),
                BlsScalar::from(0),
            ],
        );

        self.lookup_table.0.insert(
            0,
            [
                BlsScalar::from(3),
                BlsScalar::from(1),
                BlsScalar::from(4),
                BlsScalar::from(9),
            ],
        );

        self.n += 1;
    }

    /// Utility function that allows to check on the "front-end"
    /// side of the PLONK implementation if the identity polynomial
    /// is satisfied for each one of the [`StandardComposer`]'s gates.
    ///
    /// The recommended usage is to derive the std output and the std error to a
    /// text file and analyze there the gates.
    ///
    /// # Panic
    /// The function by itself will print each circuit gate info until one of
    /// the gates does not satisfy the equation or there are no more gates. If
    /// the cause is an unsatisfied gate equation, the function will panic.
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

            #[cfg(all(feature = "trace-print", feature = "std"))]
            std::println!(
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

    /// Adds a plookup gate to the circuit with its corresponding
    /// constraints.
    ///
    /// This type of gate is usually used when we need to have
    /// the largest amount of performance and the minimum circuit-size
    /// possible. Since it allows the end-user to set every selector coefficient
    /// as scaling value on the gate eq.
    pub fn plookup_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        d: Option<Variable>,
        pi: BlsScalar,
    ) -> Variable {
        // Check if advice wire has a value
        let d = match d {
            Some(var) => var,
            None => self.zero_var,
        };

        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);
        self.w_4.push(d);

        // Add selector vectors
        self.q_l.push(BlsScalar::zero());
        self.q_r.push(BlsScalar::zero());
        self.q_o.push(BlsScalar::zero());
        self.q_c.push(BlsScalar::zero());
        self.q_4.push(BlsScalar::zero());
        self.q_arith.push(BlsScalar::zero());
        self.q_m.push(BlsScalar::zero());
        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());

        // For a lookup gate, only one selector poly is
        // turned on as the output is inputted directly
        self.q_lookup.push(BlsScalar::one());

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }

    /// When StandardComposer is initialised, it spawns a dummy table
    /// with 3 entries that should not be removed. This function appends
    /// its input table to the composer's dummy table
    pub fn append_lookup_table(&mut self, table: &PlookupTable4Arity) {
        table.0.iter().for_each(|k| self.lookup_table.0.push(*k))
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment_scheme::kzg10::PublicParameters;
    use crate::constraint_system::helper::*;
    use crate::plookup::PlookupTable4Arity;
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
    fn test_gadget() {
        let mut t = PlookupTable4Arity::new();
        t.insert_special_row(
            BlsScalar::from(12),
            BlsScalar::from(12),
            BlsScalar::from(12),
            BlsScalar::from(12),
        );
        t.insert_special_row(
            BlsScalar::from(3),
            BlsScalar::from(0),
            BlsScalar::from(12),
            BlsScalar::from(341),
        );
        t.insert_special_row(
            BlsScalar::from(341),
            BlsScalar::from(341),
            BlsScalar::from(10),
            BlsScalar::from(10),
        );
        let res = gadget_plookup_tester(
            |composer| {
                let bit_1 = composer.add_input(BlsScalar::one());
                let bit_0 = composer.zero_var();

                let choice_a = composer.add_input(BlsScalar::from(10u64));
                let choice_b = composer.add_input(BlsScalar::from(20u64));

                let choice =
                    composer.conditional_select(bit_1, choice_a, choice_b);
                composer.assert_equal(choice, choice_a);

                let choice =
                    composer.conditional_select(bit_0, choice_a, choice_b);
                composer.assert_equal(choice, choice_b);
            },
            65,
            t,
        );
        assert!(res.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_gadget_fail() {
        let mut t = PlookupTable4Arity::new();
        t.insert_special_row(
            BlsScalar::from(12),
            BlsScalar::from(12),
            BlsScalar::from(12),
            BlsScalar::from(12),
        );
        let res = gadget_plookup_tester(
            |composer| {
                let twelve = composer
                    .add_witness_to_circuit_description(BlsScalar::from(12));
                let three = composer
                    .add_witness_to_circuit_description(BlsScalar::from(3));
                composer.plookup_gate(
                    twelve,
                    twelve,
                    twelve,
                    Some(three),
                    BlsScalar::zero(),
                );
            },
            65,
            t,
        );
        assert!(res.is_err());
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

    #[test]
    fn test_plookup_full() {
        let public_parameters =
            PublicParameters::setup(2 * 70, &mut OsRng).unwrap();

        // Create a prover struct
        let mut prover = Prover::new(b"test");

        prover.cs.lookup_table.insert_multi_mul(0, 3);

        // add to trans
        prover.key_transcript(b"key", b"additional seed information");

        let output = prover.cs.lookup_table.lookup(
            BlsScalar::from(2),
            BlsScalar::from(3),
            BlsScalar::one(),
        );

        let two = prover
            .cs
            .add_witness_to_circuit_description(BlsScalar::from(2));
        let three = prover
            .cs
            .add_witness_to_circuit_description(BlsScalar::from(3));
        let result = prover
            .cs
            .add_witness_to_circuit_description(output.unwrap());
        let one = prover
            .cs
            .add_witness_to_circuit_description(BlsScalar::one());

        prover
            .cs
            .plookup_gate(two, three, result, Some(one), BlsScalar::one());
        prover
            .cs
            .plookup_gate(two, three, result, Some(one), BlsScalar::one());
        prover
            .cs
            .plookup_gate(two, three, result, Some(one), BlsScalar::one());
        prover
            .cs
            .plookup_gate(two, three, result, Some(one), BlsScalar::one());
        prover
            .cs
            .plookup_gate(two, three, result, Some(one), BlsScalar::one());

        prover.cs.big_add(
            (BlsScalar::one(), two),
            (BlsScalar::one(), three),
            None,
            BlsScalar::zero(),
            Some(BlsScalar::zero()),
        );

        // Commit Key
        let (ck, _) = public_parameters.trim(2 * 70).unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        // Once the prove method is called, the public inputs are cleared
        // So pre-fetch these before calling Prove
        let public_inputs = prover.cs.construct_dense_pi_vec();

        (prover.prove(&ck).unwrap(), public_inputs);
    }

    #[test]
    #[ignore]
    fn test_plookup_proof() {
        let public_parameters =
            PublicParameters::setup(2 * 30, &mut OsRng).unwrap();

        // Create a prover struct
        let mut prover = Prover::new(b"demo");

        // Add gadgets
        dummy_gadget_plookup(4, prover.mut_cs());
        prover.cs.lookup_table.insert_multi_mul(0, 3);
        // prover.cs.
        // Commit Key
        let (ck, _) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        let public_inputs = prover.cs.construct_dense_pi_vec();

        let proof = prover.prove(&ck).unwrap();

        // Verifier
        //
        let mut verifier = Verifier::new(b"demo");

        // Add gadgets
        dummy_gadget_plookup(4, verifier.mut_cs());

        // Commit and Verifier Key
        let (ck, vk) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess
        verifier.preprocess(&ck).unwrap();

        assert!(verifier.verify(&proof, &vk, &public_inputs).is_ok());
    }
}

#[cfg(feature = "std")]
extern crate test;

#[cfg(feature = "std")]
#[cfg(test)]
mod benches {
    use super::super::helper::*;
    use super::*;
    use crate::commitment_scheme::kzg10::PublicParameters;
    use crate::constraint_system::helper::gadget_plookup_tester;
    use crate::plookup::{PlookupTable4Arity, PreprocessedTable4Arity};
    use crate::proof_system::{Prover, Verifier};
    use rand_core::OsRng;
    use test::Bencher;

    // XXX: Fix poly
    #[ignore]
    #[bench]
    fn bench_plookup_full(b: &mut Bencher) {
        let public_parameters =
            PublicParameters::setup(2 * 30, &mut OsRng).unwrap();

        // Create a prover struct
        let mut prover = Prover::new(b"demo");

        // Add gadgets
        dummy_gadget_plookup(4, prover.mut_cs());
        prover.cs.lookup_table.insert_multi_mul(0, 3);

        let output = prover.cs.lookup_table.lookup(
            BlsScalar::from(2),
            BlsScalar::from(3),
            BlsScalar::one(),
        );

        let two = prover
            .cs
            .add_witness_to_circuit_description(BlsScalar::from(2));
        let three = prover
            .cs
            .add_witness_to_circuit_description(BlsScalar::from(3));
        let result = prover
            .cs
            .add_witness_to_circuit_description(output.unwrap());
        let one = prover
            .cs
            .add_witness_to_circuit_description(BlsScalar::one());

        (0..usize::pow(2, 10)).for_each(|_| {
            prover.cs.plookup_gate(
                two,
                three,
                result,
                Some(one),
                BlsScalar::one(),
            );
            prover.cs.plookup_gate(
                two,
                three,
                result,
                Some(one),
                BlsScalar::one(),
            );
            prover.cs.plookup_gate(
                two,
                three,
                result,
                Some(one),
                BlsScalar::one(),
            );
            prover.cs.plookup_gate(
                two,
                three,
                result,
                Some(one),
                BlsScalar::one(),
            );
            prover.cs.plookup_gate(
                two,
                three,
                result,
                Some(one),
                BlsScalar::one(),
            );
            prover
                .cs
                .plookup_gate(two, two, two, Some(two), BlsScalar::one());
        });

        // prover.cs.
        // Commit Key
        let (ck, _) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        let public_inputs = prover.cs.public_inputs_sparse_store.clone();
        let lookup_table = prover.cs.lookup_table.clone();

        b.iter(|| prover.prove(&ck).unwrap());
    }
}
