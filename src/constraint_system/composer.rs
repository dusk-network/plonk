// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A `Composer` could be understood as some sort of Trait that is actually
//! defining some kind of Circuit Builder for PLONK.
//!
//! In that sense, here we have the implementation of the [`TurboComposer`]
//! which has been designed in order to provide the maximum amount of
//! performance while having a big scope in utility terms.
//!
//! It allows us not only to build Add and Mul gates but also to build
//! ECC op. gates, Range checks, Logical gates (Bitwise ops) etc.

// Gate fn's have a large number of attributes but
// it is intended to be like this in order to provide
// maximum performance and minimum circuit sizes.

use crate::constraint_system::{Constraint, Selector, WiredWitness, Witness};
use crate::permutation::Permutation;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use hashbrown::HashMap;

/// The TurboComposer is the circuit-builder tool that the `dusk-plonk`
/// repository provides so that circuit descriptions can be written, stored and
/// transformed into a [`Proof`](crate::proof_system::Proof) at some point.
///
/// A TurboComposer stores all of the circuit information, this one being
/// all of the witness and circuit descriptors info (values, positions in the
/// circuits, gates and Wires that occupy..), the public inputs, the connection
/// relationships between the witnesses and how they're represented as Wires (so
/// basically the Permutation argument etc..).
///
/// The TurboComposer also grants us a way to introduce our secret witnesses in
/// into the circuit description as well as the public inputs. We can do this
/// with methods like [`TurboComposer::append_witness`].
///
/// The TurboComposer also contains as associated functions all the necessary
/// tools to be able to instrument the circuits that the user needs
/// through the addition of gates. There are functions that may add a single
/// gate to the circuit as for example [`TurboComposer::gate_add`] and others
/// that can add several gates to the circuit description such as
/// [`TurboComposer::component_select`].
///
/// Each gate or group of gates adds a specific functionality or operation to
/// the circuit description, and so, that's why we can understand the
/// TurboComposer as a builder.
#[derive(Debug)]
pub struct TurboComposer {
    /// Number of arithmetic gates in the circuit
    pub(crate) n: usize,

    // Constraint vectors
    /// Multiplier selector
    pub(crate) q_m: Vec<BlsScalar>,
    /// Left wire selector
    pub(crate) q_l: Vec<BlsScalar>,
    /// Right wire selector
    pub(crate) q_r: Vec<BlsScalar>,
    /// Output wire selector
    pub(crate) q_o: Vec<BlsScalar>,
    /// Constant wire selector
    pub(crate) q_c: Vec<BlsScalar>,
    /// Fourth wire selector added for efficiency of implementation
    pub(crate) q_4: Vec<BlsScalar>,
    /// Arithmetic wire selector added for efficiency of implementation
    pub(crate) q_arith: Vec<BlsScalar>,
    /// Range selector added for efficiency of implementation
    pub(crate) q_range: Vec<BlsScalar>,
    /// Logic selector added for efficiency of implementation
    pub(crate) q_logic: Vec<BlsScalar>,
    /// Fixed base group addition selector added for efficiency of
    /// implementation
    pub(crate) q_fixed_group_add: Vec<BlsScalar>,
    /// Variable base group addition selector added for efficiency of
    /// implementation
    pub(crate) q_variable_group_add: Vec<BlsScalar>,

    /// Sparse representation of the Public Inputs linking the positions of the
    /// non-zero ones to it's actual values.
    pub(crate) public_inputs_sparse_store: BTreeMap<usize, BlsScalar>,

    // Witness vectors
    /// Left wire witness vector.
    pub(crate) a_w: Vec<Witness>,
    /// Right wire witness vector.
    pub(crate) b_w: Vec<Witness>,
    /// Output wire witness vector.
    pub(crate) c_w: Vec<Witness>,
    /// Fourth wire witness vector added for efficiency of implementation.
    pub(crate) d_w: Vec<Witness>,

    /// These are the actual witness values.
    pub(crate) witnesses: HashMap<Witness, BlsScalar>,

    /// Permutation argument.
    pub(crate) perm: Permutation,
}

impl TurboComposer {
    /// Returns a [`Witness`] representation of zero.
    ///
    /// Every [`TurboComposer`] is initialized with a circuit description
    /// containing a representation of zero. This function will return the
    /// index of that representation.
    pub const fn constant_zero() -> Witness {
        Witness::new(0)
    }

    /// Return the number of gates in the circuit
    pub const fn gates(&self) -> usize {
        self.n
    }

    /// Evaluate the runtime value of a witness
    ///
    /// # Safety
    ///
    /// Witness evaluation inside a gadget isn't expected and could produce an
    /// unsound circuit (different circuit representation for the same code).
    ///
    /// Calling this function performs operations outside the circuit.
    pub unsafe fn evaluate_witness(&self, witness: &Witness) -> &BlsScalar {
        &self.witnesses[witness]
    }

    /// Constructs a dense vector of the Public Inputs from the positions and
    /// the sparse vector that contains the values.
    pub(crate) fn to_dense_public_inputs(&self) -> Vec<BlsScalar> {
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
    pub fn public_input_indexes(&self) -> Vec<usize> {
        self.public_inputs_sparse_store
            .keys()
            .copied()
            .collect::<Vec<usize>>()
    }
}

impl Default for TurboComposer {
    fn default() -> Self {
        Self::new()
    }
}

impl TurboComposer {
    /// Generates a new empty `TurboComposer` with all of it's fields set to
    /// hold an initial capacity of 0.
    ///
    /// # Note
    ///
    /// The usage of this may cause lots of re-allocations since the `Composer`
    /// holds `Vec` for every polynomial, and these will need to be re-allocated
    /// each time the circuit grows considerably.
    pub(crate) fn new() -> Self {
        TurboComposer::with_size(0)
    }

    /// Constrain a scalar into the circuit description and return an allocated
    /// [`Witness`] with its value
    pub fn append_constant<T: Into<BlsScalar>>(&mut self, value: T) -> Witness {
        let scalar = value.into();
        let witness = self.append_witness(scalar);

        self.assert_equal_constant(witness, scalar, None);

        witness
    }

    /// Creates a new circuit with an expected circuit size.
    /// This will allow for less reallocations when building the circuit
    /// since the `Vec`s will already have an appropriate allocation at the
    /// beginning of the composing stage.
    pub(crate) fn with_size(size: usize) -> Self {
        let mut composer = TurboComposer {
            n: 0,

            q_m: Vec::with_capacity(size),
            q_l: Vec::with_capacity(size),
            q_r: Vec::with_capacity(size),
            q_o: Vec::with_capacity(size),
            q_c: Vec::with_capacity(size),
            q_4: Vec::with_capacity(size),
            q_arith: Vec::with_capacity(size),
            q_range: Vec::with_capacity(size),
            q_logic: Vec::with_capacity(size),
            q_fixed_group_add: Vec::with_capacity(size),
            q_variable_group_add: Vec::with_capacity(size),
            public_inputs_sparse_store: BTreeMap::new(),

            a_w: Vec::with_capacity(size),
            b_w: Vec::with_capacity(size),
            c_w: Vec::with_capacity(size),
            d_w: Vec::with_capacity(size),

            witnesses: HashMap::with_capacity(size),

            perm: Permutation::new(),
        };

        // Reserve the first witness to be zero
        composer.append_constant(BlsScalar::zero());

        // Add dummy gates
        composer.append_dummy_gates();

        composer
    }

    /// Allocate a witness value into the composer and return its index.
    pub fn append_witness<T: Into<BlsScalar>>(&mut self, scalar: T) -> Witness {
        let scalar = scalar.into();

        // Get a new Witness from the permutation
        let var = self.perm.new_witness();

        // The composer now links the BlsScalar to the Witness returned from
        // the Permutation
        self.witnesses.insert(var, scalar);

        var
    }

    /// Allocate a witness value into the composer and return its index.
    ///
    /// Create a public input with the scalar
    pub fn append_public_witness<T: Into<BlsScalar>>(
        &mut self,
        scalar: T,
    ) -> Witness {
        let scalar = scalar.into();
        let witness = self.append_witness(scalar);

        self.assert_equal_constant(witness, 0, Some(-scalar));

        witness
    }

    /// Adds a width-4 poly gate.
    ///
    /// The final constraint added will enforce the following:
    /// `q_m · a · b  + q_l · a + q_r · b + q_o · o + q_4 · d + q_c + PI = 0`.
    pub fn append_gate(&mut self, s: Constraint) {
        let a = s.witness(WiredWitness::A);
        let b = s.witness(WiredWitness::B);
        let o = s.witness(WiredWitness::O);
        let d = s.witness(WiredWitness::D);

        let s = Constraint::arithmetic(&s);

        let q_m = *s.coeff(Selector::Multiplication);
        let q_l = *s.coeff(Selector::Left);
        let q_r = *s.coeff(Selector::Right);
        let q_o = *s.coeff(Selector::Output);
        let q_4 = *s.coeff(Selector::Fourth);
        let q_c = *s.coeff(Selector::Constant);
        let pi = *s.coeff(Selector::PublicInput);

        let q_arith = *s.coeff(Selector::Arithmetic);
        let q_range = *s.coeff(Selector::Range);
        let q_logic = *s.coeff(Selector::Logic);
        let q_fixed_group_add = *s.coeff(Selector::GroupAddFixedBase);
        let q_variable_group_add = *s.coeff(Selector::GroupAddVariableBase);

        self.a_w.push(a);
        self.b_w.push(b);
        self.c_w.push(o);
        self.d_w.push(d);

        // Add selector vectors
        self.q_m.push(q_m);
        self.q_l.push(q_l);
        self.q_r.push(q_r);
        self.q_o.push(q_o);
        self.q_4.push(q_4);
        self.q_c.push(q_c);

        self.q_arith.push(q_arith);
        self.q_range.push(q_range);
        self.q_logic.push(q_logic);
        self.q_fixed_group_add.push(q_fixed_group_add);
        self.q_variable_group_add.push(q_variable_group_add);

        if s.has_public_input() {
            self.public_inputs_sparse_store.insert(self.n, pi);
        }

        self.perm.add_witnesses_to_map(a, b, o, d, self.n);

        self.n += 1;
    }

    /// Constrain `a` to be equal to `constant + pi`.
    ///
    /// `constant` will be defined as part of the public circuit description.
    pub fn assert_equal_constant<C: Into<BlsScalar>>(
        &mut self,
        a: Witness,
        constant: C,
        pi: Option<BlsScalar>,
    ) {
        let constant = constant.into();
        let constraint = Constraint::new().left(1).constant(-constant).a(a);

        // TODO maybe accept `Constraint` instead of `Option<Scalar>`?
        let constraint = match pi {
            Some(pi) => constraint.public(pi),
            None => constraint,
        };

        self.append_gate(constraint);
    }

    /// Asserts `a == b` by appending a gate
    pub fn assert_equal(&mut self, a: Witness, b: Witness) {
        let constraint =
            Constraint::new().left(1).right(-BlsScalar::one()).a(a).b(b);

        self.append_gate(constraint);
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => a,
    /// bit == 0 => b,
    ///
    /// `bit` is expected to be constrained by
    /// [`TurboComposer::component_boolean`]
    pub fn component_select(
        &mut self,
        bit: Witness,
        a: Witness,
        b: Witness,
    ) -> Witness {
        debug_assert!(
            self.witnesses[&bit] == BlsScalar::one()
                || self.witnesses[&bit] == BlsScalar::zero()
        );

        // bit * a
        let constraint = Constraint::new().mult(1).a(bit).b(a);
        let bit_times_a = self.gate_mul(constraint);

        // 1 - bit
        let constraint =
            Constraint::new().left(-BlsScalar::one()).constant(1).a(bit);
        let one_min_bit = self.gate_add(constraint);

        // (1 - bit) * b
        let constraint = Constraint::new().mult(1).a(one_min_bit).b(b);
        let one_min_bit_b = self.gate_mul(constraint);

        // [ (1 - bit) * b ] + [ bit * a ]
        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .a(one_min_bit_b)
            .b(bit_times_a);
        self.gate_add(constraint)
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => value,
    /// bit == 0 => 0,
    ///
    /// `bit` is expected to be constrained by
    /// [`TurboComposer::component_boolean`]
    pub fn component_select_zero(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        debug_assert!(
            self.witnesses[&bit] == BlsScalar::one()
                || self.witnesses[&bit] == BlsScalar::zero()
        );

        let constraint = Constraint::new().mult(1).a(bit).b(value);

        self.gate_mul(constraint)
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => value,
    /// bit == 0 => 1,
    ///
    /// `bit` is expected to be constrained by
    /// [`TurboComposer::component_boolean`]
    pub fn component_select_one(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        debug_assert!(
            self.witnesses[&bit] == BlsScalar::one()
                || self.witnesses[&bit] == BlsScalar::zero()
        );

        let b = self.witnesses[&bit];
        let v = self.witnesses[&value];

        let f_x = BlsScalar::one() - b + (b * v);
        let f_x = self.append_witness(f_x);

        let constraint = Constraint::new()
            .mult(1)
            .left(-BlsScalar::one())
            .output(-BlsScalar::one())
            .constant(1)
            .a(bit)
            .b(value)
            .o(f_x);

        self.append_gate(constraint);

        f_x
    }

    /// Decomposes `scalar` into an array truncated to `N` bits (max 256).
    ///
    /// Asserts the reconstruction of the bits to be equal to `scalar`.
    ///
    /// Consume `2 · N + 1` gates
    pub fn component_decomposition<const N: usize>(
        &mut self,
        scalar: Witness,
    ) -> [Witness; N] {
        // Static assertion
        assert!(0 < N && N <= 256);

        let mut decomposition = [Self::constant_zero(); N];

        let acc = Self::constant_zero();
        let acc = self.witnesses[&scalar]
            .to_bits()
            .iter()
            .enumerate()
            .zip(decomposition.iter_mut())
            .fold(acc, |acc, ((i, w), d)| {
                *d = self.append_witness(BlsScalar::from(*w as u64));

                self.component_boolean(*d);

                let constraint = Constraint::new()
                    .left(BlsScalar::pow_of_2(i as u64))
                    .right(1)
                    .a(*d)
                    .b(acc);

                self.gate_add(constraint)
            });

        self.assert_equal(acc, scalar);

        decomposition
    }

    /// This function is used to add a blinding factor to the witness
    /// polynomials. It essentially adds two dummy gates to the circuit
    /// description which are guaranteed to always satisfy the gate equation.
    pub fn append_dummy_gates(&mut self) {
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
        let var_six = self.append_witness(BlsScalar::from(6));
        let var_one = self.append_witness(BlsScalar::from(1));
        let var_seven = self.append_witness(BlsScalar::from(7));
        let var_min_twenty = self.append_witness(-BlsScalar::from(20));
        self.a_w.push(var_six);
        self.b_w.push(var_seven);
        self.c_w.push(var_min_twenty);
        self.d_w.push(var_one);
        self.perm.add_witnesses_to_map(
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
        self.a_w.push(var_min_twenty);
        self.b_w.push(var_six);
        self.c_w.push(var_seven);
        self.d_w.push(Self::constant_zero());
        self.perm.add_witnesses_to_map(
            var_min_twenty,
            var_six,
            var_seven,
            Self::constant_zero(),
            self.n,
        );

        self.n += 1;
    }

    pub(crate) fn append_output_witness(&mut self, s: Constraint) -> Witness {
        let a = s.witness(WiredWitness::A);
        let b = s.witness(WiredWitness::B);
        let d = s.witness(WiredWitness::D);

        let a = self.witnesses[&a];
        let b = self.witnesses[&b];
        let d = self.witnesses[&d];

        let qm = s.coeff(Selector::Multiplication);
        let ql = s.coeff(Selector::Left);
        let qr = s.coeff(Selector::Right);
        let qd = s.coeff(Selector::Fourth);
        let qc = s.coeff(Selector::Constant);
        let pi = s.coeff(Selector::PublicInput);

        let x = qm * a * b + ql * a + qr * b + qd * d + qc + pi;

        let y = s.coeff(Selector::Output);
        let y: Option<BlsScalar> = y.invert().into();
        let y = -y.expect("Inconsistent internal usage of `Constraint::evaluate_output`: Output selector should not be zero");

        let o = x * y;
        self.append_witness(o)
    }

    /// Utility function that allows to check on the "front-end"
    /// side of the PLONK implementation if the identity polynomial
    /// is satisfied for each one of the [`TurboComposer`]'s gates.
    ///
    /// The recommended usage is to derive the std output and the std error to a
    /// text file and analyze there the gates.
    ///
    /// # Panic
    /// The function by itself will print each circuit gate info until one of
    /// the gates does not satisfy the equation or there are no more gates. If
    /// the cause is an unsatisfied gate equation, the function will panic.
    #[cfg(feature = "trace")]
    #[allow(dead_code)]
    pub(crate) fn check_circuit_satisfied(&self) {
        let a_w: Vec<&BlsScalar> = self
            .a_w
            .iter()
            .map(|a_w_i| self.witnesses.get(a_w_i).unwrap())
            .collect();
        let b_w: Vec<&BlsScalar> = self
            .b_w
            .iter()
            .map(|b_w_i| self.witnesses.get(b_w_i).unwrap())
            .collect();
        let c_w: Vec<&BlsScalar> = self
            .c_w
            .iter()
            .map(|c_w_i| self.witnesses.get(c_w_i).unwrap())
            .collect();
        let d_w: Vec<&BlsScalar> = self
            .d_w
            .iter()
            .map(|d_w_i| self.witnesses.get(d_w_i).unwrap())
            .collect();

        // Computes f(f-1)(f-2)(f-3)
        let delta = |f: BlsScalar| -> BlsScalar {
            let f_1 = f - BlsScalar::one();
            let f_2 = f - BlsScalar::from(2);
            let f_3 = f - BlsScalar::from(3);
            f * f_1 * f_2 * f_3
        };

        let pi_vec = self.to_dense_public_inputs();
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

            let a = a_w[i];
            let a_next = a_w[(i + 1) % self.n];
            let b = b_w[i];
            let b_next = b_w[(i + 1) % self.n];
            let c = c_w[i];
            let d = d_w[i];
            let d_next = d_w[(i + 1) % self.n];

            #[cfg(all(feature = "trace-print", feature = "std"))]
            std::println!(
                "--------------------------------------------\n
            #Gate Index = {}
            #Constraint Polynomials:\n
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
            - a_w -> {:?}\n
            - b_w -> {:?}\n
            - c_w -> {:?}\n
            - d_w -> {:?}\n",
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

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment_scheme::PublicParameters;
    use crate::constraint_system::helper::*;
    use crate::proof_system::{Prover, Verifier};
    use rand_core::OsRng;

    #[test]
    /// Tests that a circuit initially has 3 gates
    fn test_initial_gates() {
        let composer: TurboComposer = TurboComposer::new();
        // Circuit size is n+3 because
        // - We have an extra gate which forces the first witness to be zero.
        //   This is used when the advice wire is not being used.
        // - We have two gates which ensure that the permutation polynomial is
        //   not the identity and
        // - Another gate which ensures that the selector polynomials are not
        //   all zeroes
        assert_eq!(3, composer.gates())
    }

    #[allow(unused_variables)]
    #[test]
    /// Tests that an empty circuit proof passes
    fn test_minimal_circuit() {
        let res = gadget_tester(
            |composer| {
                // do nothing except add the dummy gates
                composer.append_dummy_gates();
            },
            200,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_component_select() {
        let res = gadget_tester(
            |composer| {
                let bit_1 = composer.append_witness(BlsScalar::one());
                let bit_0 = TurboComposer::constant_zero();

                let choice_a = composer.append_witness(BlsScalar::from(10u64));
                let choice_b = composer.append_witness(BlsScalar::from(20u64));

                let choice =
                    composer.component_select(bit_1, choice_a, choice_b);
                composer.assert_equal(choice, choice_a);

                let choice =
                    composer.component_select(bit_0, choice_a, choice_b);
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
        dummy_gadget(10, prover.composer_mut());

        // Commit Key
        let (ck, _) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        let public_inputs = prover.cs.to_dense_public_inputs();

        let mut proofs = Vec::new();

        // Compute multiple proofs
        for _ in 0..3 {
            proofs.push(prover.prove(&ck, &mut OsRng).unwrap());

            // Add another witness instance
            dummy_gadget(10, prover.composer_mut());
        }

        // Verifier
        //
        let mut verifier = Verifier::new(b"demo");

        // Add gadgets
        dummy_gadget(10, verifier.composer_mut());

        // Commit and Verifier Key
        let (ck, vk) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess
        verifier.preprocess(&ck).unwrap();

        for proof in proofs {
            assert!(verifier.verify(&proof, &vk, &public_inputs).is_ok());
        }
    }
}
