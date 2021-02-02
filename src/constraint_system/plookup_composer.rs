// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

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
use crate::constraint_system::Variable;
use crate::permutation::Permutation;
use dusk_bls12_381::BlsScalar;
use std::collections::HashMap;

/// A composer is a circuit builder
/// and will dictate how a circuit is built
/// We will have a default Composer called `StandardComposer`
#[derive(Debug)]
pub struct PlookupComposer {
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
    // Plookup gate wire selector
    pub(crate) q_lookup: Vec<BlsScalar>,
    /// Public inputs vector
    pub public_inputs: Vec<BlsScalar>,

    // Witness vectors
    pub(crate) w_l: Vec<Variable>,
    pub(crate) w_r: Vec<Variable>,
    pub(crate) w_o: Vec<Variable>,
    pub(crate) w_4: Vec<Variable>,

    // Lookup queries
    pub(crate) f_1: Vec<Variable>,
    pub(crate) f_2: Vec<Variable>,
    pub(crate) f_3: Vec<Variable>,
    pub(crate) f_4: Vec<Variable>,


    /// A zero variable that is a part of the circuit description.
    /// We reserve a variable to be zero in the system
    /// This is so that when a gate only uses three wires, we set the fourth wire to be
    /// the variable that references zero
    pub(crate) zero_var: Variable,

    // These are the actual variable values
    // N.B. They should not be exposed to the end user once added into the composer
    pub(crate) variables: HashMap<Variable, BlsScalar>,

    pub(crate) perm: Permutation,
}


impl PlookupComposer {
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
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_o: BlsScalar,
        q_4: BlsScalar,
        q_c: BlsScalar,
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
        self.q_l.push(q_l);
        self.q_r.push(q_r);
        self.q_o.push(q_o);
        self.q_c.push(q_c);
        self.q_4.push(q_4);
        self.q_arith.push(BlsScalar::zero());
        self.q_m.push(BlsScalar::zero());
        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());

        // For a lookup gate, only one selector poly is 
        // turned on as the output is inputted directly
        self.q_lookup.push(BlsScalar::one());


        self.public_inputs.push(pi);

        self.perm.add_variables_to_map(a, b, c, d, self.n);

        self.n += 1;

        c
    }
}