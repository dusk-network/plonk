// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::AllocatedScalar;
use crate::constraint_system::TurboComposer;
use dusk_bls12_381::BlsScalar;

impl TurboComposer {
    /// Adds a boolean constraint (also known as binary constraint) where
    /// the gate eq. will enforce that the
    /// [`Variable`](crate::constraint_system::variable::Variable) received is
    /// either `0` or `1` by adding a constraint in the circuit.
    ///
    /// Note that using this constraint with whatever [`AllocatedScalar`] that
    /// is not representing a value equalling 0 or 1, will always force the
    /// equation to fail.
    pub fn boolean_gate(&mut self, a: AllocatedScalar) -> AllocatedScalar {
        self.w_l.push(a.into());
        self.w_r.push(a.into());
        self.w_o.push(a.into());
        self.w_4.push(self.zero_var);

        self.q_m.push(BlsScalar::one());
        self.q_l.push(BlsScalar::zero());
        self.q_r.push(BlsScalar::zero());
        self.q_o.push(-BlsScalar::one());
        self.q_c.push(BlsScalar::zero());
        self.q_4.push(BlsScalar::zero());
        self.q_arith.push(BlsScalar::one());

        self.q_range.push(BlsScalar::zero());
        self.q_logic.push(BlsScalar::zero());
        self.q_fixed_group_add.push(BlsScalar::zero());
        self.q_variable_group_add.push(BlsScalar::zero());

        self.perm
            .add_variables_to_map(a, a, a, self.allocated_zero(), self.n);

        self.n += 1;

        a
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::super::helper::*;
    use dusk_bls12_381::BlsScalar;
    #[test]
    fn test_correct_bool_gate() {
        let res = gadget_tester(
            |composer| {
                let zero = composer.allocated_zero();
                let one = composer.add_input(BlsScalar::one());

                composer.boolean_gate(zero);
                composer.boolean_gate(one);
            },
            32,
        );
        assert!(res.is_ok())
    }

    #[test]
    fn test_incorrect_bool_gate() {
        let res = gadget_tester(
            |composer| {
                let zero = composer.add_input(BlsScalar::from(5));
                let one = composer.add_input(BlsScalar::one());

                composer.boolean_gate(zero);
                composer.boolean_gate(one);
            },
            32,
        );
        assert!(res.is_err())
    }
}
