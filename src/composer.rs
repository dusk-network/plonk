// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! PLONK turbo composer definitions

use alloc::vec::Vec;
use core::ops;

use dusk_bls12_381::BlsScalar;
use hashbrown::HashMap;

use crate::error::Error;
use crate::runtime::{Runtime, RuntimeEvent};

mod bits;
mod circuit;
mod compress;
mod constraint_system;
mod fixed_base;
mod gate;
mod logic;
mod point;
mod range;
mod select;
mod truncate;

#[cfg(test)]
mod tests;

pub(crate) mod permutation;

pub use circuit::Circuit;
pub use constraint_system::{
    Constraint, TorsionFreeWitnessPoint, Witness, WitnessPoint,
};
pub(crate) use constraint_system::{Selector, WireData, WiredWitness};
pub use gate::Gate;
pub(crate) use permutation::Permutation;

/// Construct and prove circuits
#[derive(Debug, Clone)]
pub struct Composer {
    /// Constraint system gates
    pub(crate) constraints: Vec<Gate>,

    /// Sparse representation of the public inputs
    pub(crate) public_inputs: HashMap<usize, BlsScalar>,

    /// Witness values
    pub(crate) witnesses: Vec<BlsScalar>,

    /// Permutation argument.
    pub(crate) perm: Permutation,

    /// PLONK runtime controller
    pub(crate) runtime: Runtime,
}

impl ops::Index<Witness> for Composer {
    type Output = BlsScalar;

    fn index(&self, w: Witness) -> &Self::Output {
        &self.witnesses[w.index()]
    }
}

// pub trait Composer: Sized + Index<Witness, Output = BlsScalar> {
/// Circuit builder tool
impl Composer {
    /// Identity point representation inside the constraint system. The
    /// identity is the prime-order subgroup's neutral element, so it carries
    /// the [`TorsionFreeWitnessPoint`] membership by construction.
    pub const IDENTITY: TorsionFreeWitnessPoint =
        TorsionFreeWitnessPoint::new_unchecked(WitnessPoint::new(
            Self::ZERO,
            Self::ONE,
        ));
    /// `One` representation inside the constraint system.
    ///
    /// A turbo composer expects the 2nd witness to be always present and to
    /// be one.
    pub const ONE: Witness = Witness::ONE;
    /// Zero representation inside the constraint system.
    ///
    /// A turbo composer expects the first witness to be always present and to
    /// be zero.
    pub const ZERO: Witness = Witness::ZERO;

    /// Constraints count
    pub fn constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Create a [`Composer`] instance from a compressed circuit
    pub(crate) fn from_bytes(
        compressed: &[u8],
        max_constraints: usize,
    ) -> Result<Self, Error> {
        compress::CompressedCircuit::from_bytes(compressed, max_constraints)
    }

    /// Allocate a witness value into the composer and return its index.
    fn append_witness_internal(&mut self, witness: BlsScalar) -> Witness {
        let n = self.witnesses.len();

        // Get a new Witness from the permutation
        self.perm.new_witness();

        // Bind the allocated witness
        self.witnesses.push(witness);

        Witness::new(n)
    }

    /// Append a new width-4 gate/constraint.
    fn append_custom_gate_internal(&mut self, constraint: Constraint) {
        let n = self.constraints.len();

        let a = constraint.witness(WiredWitness::A);
        let b = constraint.witness(WiredWitness::B);
        let c = constraint.witness(WiredWitness::C);
        let d = constraint.witness(WiredWitness::D);

        let q_m = *constraint.coeff(Selector::Multiplication);
        let q_l = *constraint.coeff(Selector::Left);
        let q_r = *constraint.coeff(Selector::Right);
        let q_o = *constraint.coeff(Selector::Output);
        let q_f = *constraint.coeff(Selector::Fourth);
        let q_c = *constraint.coeff(Selector::Constant);

        let q_arith = *constraint.coeff(Selector::Arithmetic);
        let q_range = *constraint.coeff(Selector::Range);
        let q_logic = *constraint.coeff(Selector::Logic);
        let q_fixed_group_add = *constraint.coeff(Selector::GroupAddFixedBase);
        let q_variable_group_add =
            *constraint.coeff(Selector::GroupAddVariableBase);

        let gate = Gate {
            q_m,
            q_l,
            q_r,
            q_o,
            q_f,
            q_c,
            q_arith,
            q_range,
            q_logic,
            q_fixed_group_add,
            q_variable_group_add,
            a,
            b,
            c,
            d,
        };

        self.constraints.push(gate);

        if constraint.has_public_input() {
            let pi = *constraint.coeff(Selector::PublicInput);

            self.public_inputs.insert(n, pi);
        }

        self.perm.add_witnesses_to_map(a, b, c, d, n);
    }

    /// PLONK runtime controller
    pub(crate) fn runtime(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

    /// Initialize the constraint system with the constants for 0 and 1 and
    /// append two dummy gates
    pub fn initialized() -> Self {
        let mut slf = Self::uninitialized();

        let zero = slf.append_witness(0);
        let one = slf.append_witness(1);

        slf.assert_equal_constant(zero, 0, None);
        slf.assert_equal_constant(one, 1, None);

        slf.append_dummy_gates();

        slf
    }

    /// Create an empty constraint system.
    ///
    /// This shouldn't be used directly; instead, use [`Self::initialized`]
    pub(crate) fn uninitialized() -> Self {
        Self {
            constraints: Vec::new(),
            public_inputs: HashMap::new(),
            witnesses: Vec::new(),
            perm: Permutation::new(),
            runtime: Runtime::new(),
        }
    }

    /// Adds blinding factors to the witness polynomials with two dummy
    /// arithmetic constraints
    fn append_dummy_gates(&mut self) {
        let six = self.append_witness(BlsScalar::from(6));
        let one = self.append_witness(BlsScalar::from(1));
        let seven = self.append_witness(BlsScalar::from(7));
        let min_twenty = self.append_witness(-BlsScalar::from(20));

        // Add a dummy constraint so that we do not have zero polynomials
        let constraint = Constraint::new()
            .mult(1)
            .left(2)
            .right(3)
            .fourth(1)
            .constant(4)
            .output(4)
            .a(six)
            .b(seven)
            .d(one)
            .c(min_twenty);

        self.append_gate(constraint);

        // Add another dummy constraint so that we do not get the identity
        // permutation
        let constraint = Constraint::new()
            .mult(1)
            .left(1)
            .right(1)
            .constant(127)
            .output(1)
            .a(min_twenty)
            .b(six)
            .c(seven);

        self.append_gate(constraint);
    }

    /// Allocate a witness value into the composer and return its index.
    pub fn append_witness<W: Into<BlsScalar>>(
        &mut self,
        witness: W,
    ) -> Witness {
        let witness = witness.into();

        let witness = self.append_witness_internal(witness);

        #[cfg(feature = "debug")]
        let v = self[witness];
        self.runtime().event(RuntimeEvent::WitnessAppended {
            #[cfg(feature = "debug")]
            w: witness,
            #[cfg(feature = "debug")]
            v,
        });

        witness
    }

    /// Append a new width-4 gate/constraint.
    pub fn append_custom_gate(&mut self, constraint: Constraint) {
        self.runtime().event(RuntimeEvent::ConstraintAppended {
            #[cfg(feature = "debug")]
            c: constraint,
        });

        self.append_custom_gate_internal(constraint)
    }

    /// Append a new width-4 gate/constraint.
    ///
    /// The constraint added will enforce the following:
    /// `q_M · a · b  + q_L · a + q_R · b + q_O · o + q_F · d + q_C + PI = 0`.
    pub fn append_gate(&mut self, constraint: Constraint) {
        let constraint = Constraint::arithmetic(&constraint);

        self.append_custom_gate(constraint)
    }

    /// Evaluate an arithmetic constraint, allocate its output, and append the
    /// gate that constrains that output to the inputs.
    ///
    /// For an invertible output selector `q_O`, this solves
    ///
    /// `q_M·a·b + q_L·a + q_R·b + q_O·c + q_F·d + q_C + PI = 0`
    ///
    /// for `c`, appends `c` as a witness, wires it into the constraint, and
    /// appends exactly one active arithmetic gate.
    ///
    /// If `q_O` is zero, no output can be solved for: this returns `None` but
    /// still appends exactly one arithmetic gate enforcing the supplied
    /// polynomial on its input witnesses.
    ///
    /// The appended gate is the soundness boundary. Computing `c` from host
    /// witness values alone is not a circuit constraint: without this row, a
    /// malicious prover could replace `c` while preserving the circuit shape.
    ///
    /// # Circuit compatibility
    ///
    /// Direct callers now receive one arithmetic row and must regenerate their
    /// circuit-specific proving and verifier keys, and any cached compressed
    /// circuit description. [`Self::gate_add`] and [`Self::gate_mul`] still
    /// emit exactly one row, so their circuit layouts are unchanged.
    pub fn append_evaluated_output(
        &mut self,
        mut s: Constraint,
    ) -> Option<Witness> {
        let a = s.witness(WiredWitness::A);
        let b = s.witness(WiredWitness::B);
        let d = s.witness(WiredWitness::D);

        let a = self[a];
        let b = self[b];
        let d = self[d];

        let qm = s.coeff(Selector::Multiplication);
        let ql = s.coeff(Selector::Left);
        let qr = s.coeff(Selector::Right);
        let qf = s.coeff(Selector::Fourth);
        let qc = s.coeff(Selector::Constant);
        let pi = s.coeff(Selector::PublicInput);

        let x = qm * a * b + ql * a + qr * b + qf * d + qc + pi;

        let y = s.coeff(Selector::Output);

        // Invert is an expensive operation; in most cases, `q_O` is going to be
        // either 1 or -1, so we can optimize these
        let c = {
            const ONE: BlsScalar = BlsScalar::one();
            const MINUS_ONE: BlsScalar = BlsScalar([
                0xfffffffd00000003,
                0xfb38ec08fffb13fc,
                0x99ad88181ce5880f,
                0x5bc8f5f97cd877d8,
            ]);

            // Can't use a match pattern here since `BlsScalar` doesn't derive
            // `PartialEq`
            if y == &ONE {
                Some(-x)
            } else if y == &MINUS_ONE {
                Some(x)
            } else {
                y.invert().map(|y| x * (-y))
            }
        };

        let output = c.map(|c| self.append_witness(c));
        if let Some(output) = output {
            s = s.c(output);
        }
        self.append_gate(s);

        output
    }

    /// Constrain a scalar into the circuit description and return an allocated
    /// [`Witness`] with its value
    pub fn append_constant<C: Into<BlsScalar>>(
        &mut self,
        constant: C,
    ) -> Witness {
        let constant = constant.into();
        let witness = self.append_witness(constant);

        self.assert_equal_constant(witness, constant, None);

        witness
    }

    /// Allocate a witness value into the composer and return its index.
    ///
    /// Create a public input with the scalar
    pub fn append_public<P: Into<BlsScalar>>(&mut self, public: P) -> Witness {
        let public = public.into();
        let witness = self.append_witness(public);

        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(witness)
            .public(public);
        self.append_gate(constraint);

        witness
    }

    /// Asserts `a == b` by appending a gate
    pub fn assert_equal(&mut self, a: Witness, b: Witness) {
        let constraint =
            Constraint::new().left(1).right(-BlsScalar::one()).a(a).b(b);

        self.append_gate(constraint);
    }

    /// Constrain `a` to be equal to `constant + pi`.
    ///
    /// `constant` will be defined as part of the public circuit description.
    pub fn assert_equal_constant<C: Into<BlsScalar>>(
        &mut self,
        a: Witness,
        constant: C,
        public: Option<BlsScalar>,
    ) {
        let constant = constant.into();
        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(a)
            .constant(constant);
        let constraint =
            public.map(|p| constraint.public(p)).unwrap_or(constraint);

        self.append_gate(constraint);
    }

    /// Evaluate and return `o` by appending a new constraint into the circuit.
    ///
    /// Set `q_O = (-1)` and override the output of the constraint with:
    /// `c := q_L · a + q_R · b + q_F · d + q_C + PI`
    pub fn gate_add(&mut self, s: Constraint) -> Witness {
        let s = Constraint::arithmetic(&s).output(-BlsScalar::one());

        self.append_evaluated_output(s)
            .expect("output selector is -1")
    }

    /// Evaluate and return `c` by appending a new constraint into the circuit.
    ///
    /// Set `q_O = (-1)` and override the output of the constraint with:
    /// `c := q_M · a · b + q_F · d + q_C + PI`
    pub fn gate_mul(&mut self, s: Constraint) -> Witness {
        let s = Constraint::arithmetic(&s).output(-BlsScalar::one());

        self.append_evaluated_output(s)
            .expect("output selector is -1")
    }

    /// Prove a circuit with a composer initialized with dummy gates
    pub fn prove<C>(constraints: usize, circuit: &C) -> Result<Self, Error>
    where
        C: Circuit,
    {
        let mut composer = Self::initialized();

        circuit.circuit(&mut composer)?;

        // assert that the circuit has the same amount of constraints as the
        // circuit description
        let description_size = composer.constraints();
        if description_size != constraints {
            return Err(Error::InvalidCircuitSize(
                description_size,
                constraints,
            ));
        }

        composer.runtime().event(RuntimeEvent::ProofFinished);

        Ok(composer)
    }

    pub(crate) fn public_input_indexes(&self) -> Vec<usize> {
        let mut public_input_indexes: Vec<_> =
            self.public_inputs.keys().copied().collect();

        public_input_indexes.as_mut_slice().sort();

        public_input_indexes
    }

    pub(crate) fn public_inputs(&self) -> Vec<BlsScalar> {
        self.public_input_indexes()
            .iter()
            .filter_map(|idx| self.public_inputs.get(idx).copied())
            .collect()
    }

    pub(crate) fn dense_public_inputs(
        public_input_indexes: &[usize],
        public_inputs: &[BlsScalar],
        size: usize,
    ) -> Vec<BlsScalar> {
        let mut dense_public_inputs = vec![BlsScalar::zero(); size];

        public_input_indexes
            .iter()
            .zip(public_inputs.iter())
            .for_each(|(idx, pi)| dense_public_inputs[*idx] = *pi);

        dense_public_inputs
    }
}
