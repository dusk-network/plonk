// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use core::ops;

use dusk_bls12_381::BlsScalar;
use hashbrown::HashMap;

use crate::constraint_system::{Constraint, Selector, WiredWitness, Witness};
use crate::permutation::Permutation;
use crate::runtime::Runtime;

use super::{Composer, Polynomial};

/// Construct and prove circuits
#[derive(Debug, Clone)]
pub struct Builder {
    /// Constraint system gates
    pub(crate) constraints: Vec<Polynomial>,

    /// Sparse representation of the public inputs
    pub(crate) public_inputs: HashMap<usize, BlsScalar>,

    /// Witness values
    pub(crate) witnesses: Vec<BlsScalar>,

    /// Permutation argument.
    pub(crate) perm: Permutation,

    /// PLONK runtime controller
    pub(crate) runtime: Runtime,
}

impl Builder {
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

impl ops::Index<Witness> for Builder {
    type Output = BlsScalar;

    fn index(&self, w: Witness) -> &Self::Output {
        &self.witnesses[w.index()]
    }
}

impl Composer for Builder {
    fn uninitialized(capacity: usize) -> Self {
        Self {
            constraints: Vec::with_capacity(capacity),
            public_inputs: HashMap::new(),
            witnesses: Vec::with_capacity(capacity),
            perm: Permutation::new(),
            runtime: Runtime::with_capacity(capacity),
        }
    }

    fn constraints(&self) -> usize {
        self.constraints.len()
    }

    fn append_witness_internal(&mut self, witness: BlsScalar) -> Witness {
        // #[cfg(feature = "debug")]
        // println!("append_witness_internal={:?}", witness.0[0]);

        let n = self.witnesses.len();

        // Get a new Witness from the permutation
        self.perm.new_witness();

        // Bind the allocated witness
        self.witnesses.push(witness);

        Witness::new(n)
    }

    fn append_custom_gate_internal(&mut self, constraint: Constraint) {
        // #[cfg(feature = "debug")]
        // println!("append_custom_gate_internal={:?}", constraint);
        let n = self.constraints.len();

        let w_a = constraint.witness(WiredWitness::A);
        let w_b = constraint.witness(WiredWitness::B);
        let w_o = constraint.witness(WiredWitness::O);
        let w_d = constraint.witness(WiredWitness::D);

        let q_m = *constraint.coeff(Selector::Multiplication);
        let q_l = *constraint.coeff(Selector::Left);
        let q_r = *constraint.coeff(Selector::Right);
        let q_o = *constraint.coeff(Selector::Output);
        let q_c = *constraint.coeff(Selector::Constant);
        let q_d = *constraint.coeff(Selector::Fourth);

        let q_arith = *constraint.coeff(Selector::Arithmetic);
        let q_range = *constraint.coeff(Selector::Range);
        let q_logic = *constraint.coeff(Selector::Logic);
        let q_fixed_group_add = *constraint.coeff(Selector::GroupAddFixedBase);
        let q_variable_group_add =
            *constraint.coeff(Selector::GroupAddVariableBase);

        let poly = Polynomial {
            q_m,
            q_l,
            q_r,
            q_o,
            q_c,
            q_d,
            q_arith,
            q_range,
            q_logic,
            q_fixed_group_add,
            q_variable_group_add,
            w_a,
            w_b,
            w_o,
            w_d,
        };

        self.constraints.push(poly);

        if constraint.has_public_input() {
            let pi = *constraint.coeff(Selector::PublicInput);

            self.public_inputs.insert(n, pi);
        }

        self.perm.add_witnesses_to_map(w_a, w_b, w_o, w_d, n);
    }

    fn runtime(&mut self) -> &mut Runtime {
        &mut self.runtime
    }
}
