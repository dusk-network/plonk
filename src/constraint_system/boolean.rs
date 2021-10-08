// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::{Constraint, TurboComposer, Witness};
use dusk_bls12_381::BlsScalar;

impl TurboComposer {
    /// Adds a boolean constraint (also known as binary constraint) where the
    /// gate eq. will enforce that the [`Witness`] received is either `0` or `1`
    /// by adding a constraint in the circuit.
    ///
    /// Note that using this constraint with whatever [`Witness`] that
    /// is not representing a value equalling 0 or 1, will always force the
    /// equation to fail.
    pub fn gate_boolean(&mut self, a: Witness) {
        let zero = self.constant_zero();
        let constraint = Constraint::new().mul(1).output(-BlsScalar::one());

        self.append_gate(a, a, a, zero, constraint);
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
                let zero = composer.constant_zero();
                let one = composer.append_witness(BlsScalar::one());

                composer.gate_boolean(zero);
                composer.gate_boolean(one);
            },
            32,
        );
        assert!(res.is_ok())
    }

    #[test]
    fn test_incorrect_bool_gate() {
        let res = gadget_tester(
            |composer| {
                let zero = composer.append_witness(BlsScalar::from(5));
                let one = composer.append_witness(BlsScalar::one());

                composer.gate_boolean(zero);
                composer.gate_boolean(one);
            },
            32,
        );
        assert!(res.is_err())
    }
}
