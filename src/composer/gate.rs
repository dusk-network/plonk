// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

use crate::prelude::Witness;

/// Represents a gate with its associated wire data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    // Selectors
    /// Multiplier selector
    pub(crate) q_m: BlsScalar,
    /// Left wire selector
    pub(crate) q_l: BlsScalar,
    /// Right wire selector
    pub(crate) q_r: BlsScalar,
    /// Output wire selector
    pub(crate) q_o: BlsScalar,
    /// Fourth wire selector
    pub(crate) q_f: BlsScalar,
    /// Constant wire selector
    pub(crate) q_c: BlsScalar,
    /// Arithmetic wire selector
    pub(crate) q_arith: BlsScalar,
    /// Range selector
    pub(crate) q_range: BlsScalar,
    /// Logic selector
    pub(crate) q_logic: BlsScalar,
    /// Fixed base group addition selector
    pub(crate) q_fixed_group_add: BlsScalar,
    /// Variable base group addition selector
    pub(crate) q_variable_group_add: BlsScalar,

    /// Left wire witness.
    pub(crate) a: Witness,
    /// Right wire witness.
    pub(crate) b: Witness,
    /// Output wire witness.
    pub(crate) c: Witness,
    /// Fourth wire witness.
    pub(crate) d: Witness,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_is_copy_clone_and_eq() {
        let gate = Gate {
            q_m: BlsScalar::from(1u64),
            q_l: BlsScalar::from(2u64),
            q_r: BlsScalar::from(3u64),
            q_o: BlsScalar::from(4u64),
            q_f: BlsScalar::from(5u64),
            q_c: BlsScalar::from(6u64),
            q_arith: BlsScalar::one(),
            q_range: BlsScalar::zero(),
            q_logic: BlsScalar::zero(),
            q_fixed_group_add: BlsScalar::zero(),
            q_variable_group_add: BlsScalar::zero(),
            a: Witness::ZERO,
            b: Witness::ONE,
            c: Witness::new(2),
            d: Witness::new(3),
        };

        // Copy
        let gate_copy = gate;
        assert_eq!(gate, gate_copy);

        // Clone
        let gate_clone = gate_copy.clone();
        assert_eq!(gate_copy, gate_clone);

        // Debug fmt should not panic
        let _ = format!("{gate_clone:?}");
    }

    #[test]
    fn gate_partial_eq_compares_fields() {
        let mut a = Gate {
            q_m: BlsScalar::from(1u64),
            q_l: BlsScalar::from(2u64),
            q_r: BlsScalar::from(3u64),
            q_o: BlsScalar::from(4u64),
            q_f: BlsScalar::from(5u64),
            q_c: BlsScalar::from(6u64),
            q_arith: BlsScalar::one(),
            q_range: BlsScalar::zero(),
            q_logic: BlsScalar::zero(),
            q_fixed_group_add: BlsScalar::zero(),
            q_variable_group_add: BlsScalar::zero(),
            a: Witness::ZERO,
            b: Witness::ONE,
            c: Witness::new(2),
            d: Witness::new(3),
        };

        let mut b = a;
        assert_eq!(a, b);

        // Flip one field and ensure inequality.
        b.q_c = BlsScalar::from(7u64);
        assert_ne!(a, b);
    }
}
