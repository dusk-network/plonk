// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Contains the functionality of plonkup gates on top of the composer

#![allow(clippy::too_many_arguments)]

use crate::constraint_system::TurboComposer;
use crate::constraint_system::Witness;
use dusk_bls12_381::BlsScalar;

impl TurboComposer {
    /// Adds a plonkup gate to the circuit with its corresponding
    /// constraints.
    ///
    /// This type of gate is usually used when we need to have
    /// the largest amount of performance and the minimum circuit-size
    /// possible. Since it allows the end-user to set every selector coefficient
    /// as scaling value on the gate eq.
    pub fn plonkup_gate(
        &mut self,
        a: Witness,
        b: Witness,
        c: Witness,
        d: Option<Witness>,
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_o: BlsScalar,
        q_4: BlsScalar,
        q_c: BlsScalar,
        pi: BlsScalar,
    ) -> Witness {
        // Check if advice wire has a value
        let d = match d {
            Some(witness) => witness,
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
