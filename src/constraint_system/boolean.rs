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
    pub fn component_boolean(&mut self, a: Witness) {
        let zero = Self::constant_zero();
        let constraint = Constraint::new()
            .mult(1)
            .output(-BlsScalar::one())
            .a(a)
            .b(a)
            .o(a)
            .d(zero);

        self.append_gate(constraint);
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use crate::constraint_system::{helper, TurboComposer};
    use dusk_bls12_381::BlsScalar;

    #[test]
    fn test_correct_bool_gate() {
        let res = helper::gadget_tester(
            |composer| {
                let zero = TurboComposer::constant_zero();
                let one = composer.append_witness(BlsScalar::one());

                composer.component_boolean(zero);
                composer.component_boolean(one);
            },
            32,
        );
        assert!(res.is_ok())
    }

    #[test]
    fn test_incorrect_bool_gate() {
        let res = helper::gadget_tester(
            |composer| {
                let zero = composer.append_witness(BlsScalar::from(5));
                let one = composer.append_witness(BlsScalar::one());

                composer.component_boolean(zero);
                composer.component_boolean(one);
            },
            32,
        );
        assert!(res.is_err())
    }
}
