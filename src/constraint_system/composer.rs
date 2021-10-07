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

use crate::constraint_system::Witness;
use crate::permutation::Permutation;
use crate::plonkup::PlonkupTable4Arity;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use hashbrown::HashMap;

/// The TurboComposer is the circuit-builder tool that the `dusk-plonk`
/// repository provides so that circuit descriptions can be written, stored and
/// transformed into a [`Proof`](crate::proof_system::Proof) at some point.
///
/// A TurboComposer stores all of the circuit information, being this one
/// all of the witness and circuit descriptors info (values, positions in the
/// circuits, gates and Wires that occupy..), the public inputs, the connection
/// relationships between the witnesses and how they're repesented as Wires (so
/// basically the Permutation argument etc..).
///
/// The TurboComposer also grants us a way to introduce our secret witnesses in
/// a for of a [`Witness`] into the circuit description as well as the public
/// inputs. We can do this with methods like [`TurboComposer::append_witness`].
///
/// The TurboComposer also contains as associated functions all the
/// neccessary tools to be able to istrument the circuits that the user needs
/// through the addition of gates. There are functions that may add a single
/// gate to the circuit as for example [`TurboComposer::gate_add`] and others
/// that can add several gates to the circuit description such as
/// [`TurboComposer::component_select`].
///
/// Each gate or group of gates adds an specific functionallity or operation to
/// de circuit description, and so, that's why we can understand
/// the TurboComposer as a builder.
#[derive(Debug)]
pub struct TurboComposer {
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
    /// Plonkup gate wire selector
    pub(crate) q_lookup: Vec<BlsScalar>,

    /// Sparse representation of the Public Inputs linking the positions of the
    /// non-zero ones to it's actual values.
    pub(crate) public_inputs_sparse_store: BTreeMap<usize, BlsScalar>,

    // Witness vectors
    /// Left wire witness vector.
    pub(crate) w_l: Vec<Witness>,
    /// Right wire witness vector.
    pub(crate) w_r: Vec<Witness>,
    /// Output wire witness vector.
    pub(crate) w_o: Vec<Witness>,
    /// Fourth wire witness vector.
    pub(crate) w_4: Vec<Witness>,

    /// Public lookup table
    pub(crate) lookup_table: PlonkupTable4Arity,

    /// A zero Witness that is a part of the circuit description.
    /// We reserve a variable to be zero in the system
    /// This is so that when a gate only uses three wires, we set the fourth
    /// wire to be the variable that references zero
    pub(crate) constant_zero: Witness,

    /// These are the actual variable values.
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
    pub const fn constant_zero(&self) -> Witness {
        self.constant_zero
    }

    /// Return the number of gates in the circuit
    pub const fn gates(&self) -> usize {
        self.n
    }

    /// Evaluate the runtime value of a witness
    #[allow(dead_code)]
    pub(crate) fn evaluate_witness(&self, witness: &Witness) -> &BlsScalar {
        &self.witnesses[&witness]
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
    /// Generates a new empty `TurboComposer` with all of it's fields
    /// set to hold an initial capacity of 0.
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
    pub fn append_constant(&mut self, value: BlsScalar) -> Witness {
        let witness = self.append_witness(value);

        self.assert_equal_constant(witness, value, None);

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
            q_lookup: Vec::with_capacity(size),
            public_inputs_sparse_store: BTreeMap::new(),

            w_l: Vec::with_capacity(size),
            w_r: Vec::with_capacity(size),
            w_o: Vec::with_capacity(size),
            w_4: Vec::with_capacity(size),

            lookup_table: PlonkupTable4Arity::new(),

            constant_zero: Witness::new(0),

            witnesses: HashMap::with_capacity(size),

            perm: Permutation::new(),
        };

        // Reserve the first variable to be zero
        composer.constant_zero = composer.append_constant(BlsScalar::zero());

        // Add dummy gates
        composer.append_dummy_gates();

        composer
    }

    /// Allocate a witness value into the composer and return its index.
    pub fn append_witness<T: Into<BlsScalar>>(&mut self, scalar: T) -> Witness {
        let scalar = scalar.into();

        // Get a new Witness from the permutation
        let var = self.perm.new_variable();

        // The composer now links the BlsScalar to the Witness returned from
        // the Permutation
        self.witnesses.insert(var, scalar);

        var
    }

    /// Adds a width-4 poly gate.
    ///
    /// The final constraint added will enforce the following:
    /// `q_m · a · b  + q_l · a + q_r · b + q_o · o + q_4 · d + q_c + PI = 0`.
    pub fn append_gate(
        &mut self,
        a: Witness,
        b: Witness,
        o: Witness,
        d: Witness,
        q_m: BlsScalar,
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_o: BlsScalar,
        q_4: BlsScalar,
        q_c: BlsScalar,
        pi: Option<BlsScalar>,
    ) {
        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(o);
        self.w_4.push(d);

        // Add selector vectors
        self.q_m.push(q_m);
        self.q_l.push(q_l);
        self.q_r.push(q_r);
        self.q_o.push(q_o);
        self.q_4.push(q_4);
        self.q_c.push(q_c);

        self.q_arith.push(BlsScalar::one());
        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());
        self.q_lookup.push(BlsScalar::zero());

        if let Some(pi) = pi {
            debug_assert!(self.public_inputs_sparse_store.get(&self.n).is_none(), "The invariant of already having a PI inserted for this position should never exist");

            self.public_inputs_sparse_store.insert(self.n, pi);
        }

        self.perm.add_variables_to_map(a, b, o, d, self.n);

        self.n += 1;
    }

    /// Constrain `a` to be equal to `constant + pi`.
    ///
    /// `constant` will be defined as part of the public circuit description.
    pub fn assert_equal_constant(
        &mut self,
        a: Witness,
        constant: BlsScalar,
        pi: Option<BlsScalar>,
    ) {
        let zero = self.constant_zero();

        self.append_gate(
            a,
            zero,
            zero,
            zero,
            BlsScalar::zero(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            -constant,
            pi,
        );
    }

    /// Asserts `a == b` by appending a gate
    pub fn assert_equal(&mut self, a: Witness, b: Witness) {
        let zero = self.constant_zero();

        self.append_gate(
            a,
            b,
            zero,
            zero,
            BlsScalar::zero(),
            BlsScalar::one(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => a,
    /// bit == 0 => b,
    ///
    /// `bit` is expected to be constrained by [`TurboComposer::gate_boolean`]
    pub fn component_select(
        &mut self,
        bit: Witness,
        a: Witness,
        b: Witness,
    ) -> Witness {
        // bit * a
        let bit_times_a = self.gate_mul(
            bit,
            a,
            self.constant_zero(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // 1 - bit
        let one_min_bit = self.gate_add(
            bit,
            self.constant_zero(),
            self.constant_zero(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::one(),
            None,
        );

        // (1 - bit) * b
        let one_min_bit_b = self.gate_mul(
            one_min_bit,
            b,
            self.constant_zero(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // [ (1 - bit) * b ] + [ bit * a ]
        self.gate_add(
            one_min_bit_b,
            bit_times_a,
            self.constant_zero(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        )
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => value,
    /// bit == 0 => 0,
    ///
    /// `bit` is expected to be constrained by [`TurboComposer::gate_boolean`]
    pub fn gate_select_zero(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        // returns bit * value
        self.gate_mul(
            bit,
            value,
            self.constant_zero(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        )
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => value,
    /// bit == 0 => 1,
    ///
    /// `bit` is expected to be constrained by [`TurboComposer::gate_boolean`]
    pub fn gate_select_one(&mut self, bit: Witness, value: Witness) -> Witness {
        let b = self.witnesses[&bit];
        let v = self.witnesses[&value];
        let zero = self.constant_zero();

        let f_x = BlsScalar::one() - b + (b * v);
        let f_x = self.append_witness(f_x);

        self.append_gate(
            bit,
            value,
            f_x,
            zero,
            BlsScalar::one(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::one(),
            None,
        );

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

        let mut decomposition = [self.constant_zero(); N];

        let acc = self.constant_zero();
        let acc = self.witnesses[&scalar]
            .to_bits()
            .iter()
            .enumerate()
            .zip(decomposition.iter_mut())
            .fold(acc, |acc, ((i, w), d)| {
                *d = self.append_witness(BlsScalar::from(*w as u64));

                self.gate_boolean(*d);
                self.gate_add(
                    *d,
                    acc,
                    self.constant_zero(),
                    BlsScalar::pow_of_2(i as u64),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
                    None,
                )
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
        self.q_lookup.push(BlsScalar::one());
        let var_six = self.append_witness(BlsScalar::from(6));
        let var_one = self.append_witness(BlsScalar::from(1));
        let var_seven = self.append_witness(BlsScalar::from(7));
        let var_min_twenty = self.append_witness(-BlsScalar::from(20));
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
        self.w_4.push(self.constant_zero());
        self.perm.add_variables_to_map(
            var_min_twenty,
            var_six,
            var_seven,
            self.constant_zero(),
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
        let w_l: Vec<&BlsScalar> = self
            .w_l
            .iter()
            .map(|w_l_i| self.witnesses.get(&w_l_i).unwrap())
            .collect();
        let w_r: Vec<&BlsScalar> = self
            .w_r
            .iter()
            .map(|w_r_i| self.witnesses.get(&w_r_i).unwrap())
            .collect();
        let w_o: Vec<&BlsScalar> = self
            .w_o
            .iter()
            .map(|w_o_i| self.witnesses.get(&w_o_i).unwrap())
            .collect();
        let w_4: Vec<&BlsScalar> = self
            .w_4
            .iter()
            .map(|w_4_i| self.witnesses.get(&w_4_i).unwrap())
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

    /// Adds a plonkup gate to the circuit with its corresponding
    /// gates.
    ///
    /// This type of gate is usually used when we need to have
    /// the largest amount of performance and the minimum circuit-size
    /// possible. Since it allows the end-user to set every selector coefficient
    /// as scaling value on the gate eq.
    pub fn append_plonkup_gate(
        &mut self,
        a: Witness,
        b: Witness,
        c: Witness,
        d: Witness,
        pi: Option<BlsScalar>,
    ) -> Witness {
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

        if let Some(pi) = pi {
            debug_assert!(self.public_inputs_sparse_store.get(&self.n).is_none(), "The invariant of already having a PI inserted for this position should never exist");

            self.public_inputs_sparse_store.insert(self.n, pi);
        }

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }

    /// When [`TurboComposer`] is initialised, it spawns a dummy table
    /// with 3 entries that should not be removed. This function appends
    /// its input table to the composer's dummy table
    pub fn append_plonkup_table(&mut self, table: &PlonkupTable4Arity) {
        table.0.iter().for_each(|k| self.lookup_table.0.push(*k))
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment_scheme::PublicParameters;
    use crate::constraint_system::helper::*;
    use crate::error::Error;
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
                let bit_0 = composer.constant_zero();

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
    fn test_gadget() {
        let mut t = PlonkupTable4Arity::new();
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
        let res = gadget_plonkup_tester(
            |composer| {
                let bit_1 = composer.append_witness(BlsScalar::one());
                let bit_0 = composer.constant_zero();

                let choice_a = composer.append_witness(BlsScalar::from(10u64));
                let choice_b = composer.append_witness(BlsScalar::from(20u64));

                let choice =
                    composer.component_select(bit_1, choice_a, choice_b);
                composer.assert_equal(choice, choice_a);

                let choice =
                    composer.component_select(bit_0, choice_a, choice_b);
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
        let mut t = PlonkupTable4Arity::new();
        t.insert_special_row(
            BlsScalar::from(12),
            BlsScalar::from(12),
            BlsScalar::from(12),
            BlsScalar::from(12),
        );
        let res = gadget_plonkup_tester(
            |composer| {
                let twelve = composer.append_constant(BlsScalar::from(12));
                let three = composer.append_constant(BlsScalar::from(3));

                composer
                    .append_plonkup_gate(twelve, twelve, twelve, three, None);
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
        dummy_gadget(10, prover.composer_mut());

        // Commit Key
        let (ck, _) = public_parameters.trim(2 * 20).unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        let public_inputs = prover.cs.to_dense_public_inputs();

        let mut proofs = Vec::new();

        // Compute multiple proofs
        for _ in 0..3 {
            proofs.push(prover.prove(&ck).unwrap());

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

    #[test]
    fn test_plonkup_full() {
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

        let two = prover.cs.append_constant(BlsScalar::from(2));
        let three = prover.cs.append_constant(BlsScalar::from(3));
        let result = prover.cs.append_constant(output.unwrap());
        let one = prover.cs.append_constant(BlsScalar::one());
        let zero = prover.cs.constant_zero();

        prover.cs.append_plonkup_gate(two, three, result, one, None);
        prover.cs.append_plonkup_gate(two, three, result, one, None);
        prover.cs.append_plonkup_gate(two, three, result, one, None);
        prover.cs.append_plonkup_gate(two, three, result, one, None);
        prover.cs.append_plonkup_gate(two, three, result, one, None);

        prover.cs.gate_add(
            two,
            three,
            zero,
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            None,
        );

        // Commit Key
        let (ck, _) = public_parameters.trim(2 * 70).unwrap();

        // Preprocess circuit
        prover.preprocess(&ck).unwrap();

        // Once the prove method is called, the public inputs are cleared
        // So pre-fetch these before calling Prove
        let public_inputs = prover.cs.to_dense_public_inputs();

        (prover.prove(&ck).unwrap(), public_inputs);
    }

    #[test]
    fn test_plonkup_proof() -> Result<(), Error> {
        let public_parameters = PublicParameters::setup(1 << 8, &mut OsRng)?;

        // Create a prover struct
        let mut prover = Prover::new(b"test");
        let mut verifier = Verifier::new(b"test");

        // Add gadgets
        dummy_gadget_plonkup(4, prover.composer_mut());
        prover.cs.lookup_table.insert_multi_mul(0, 3);

        dummy_gadget_plonkup(4, verifier.composer_mut());
        verifier.cs.lookup_table.insert_multi_mul(0, 3);

        // Commit and verifier key
        let (ck, vk) = public_parameters.trim(1 << 7)?;

        // Preprocess circuit
        prover.preprocess(&ck)?;
        verifier.preprocess(&ck)?;

        let public_inputs = prover.cs.to_dense_public_inputs();

        let proof = prover.prove(&ck)?;

        assert!(verifier.verify(&proof, &vk, &public_inputs).is_ok());

        Ok(())
    }
}
