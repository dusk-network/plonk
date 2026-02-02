// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module holds the components needed in the Constraint System.
//! The components used are Variables, Witness and Wires.

/// Stores the data for a specific wire in an arithmetic circuit
/// This data is the gate index and the type of wire
/// Left(1) signifies that this wire belongs to the first gate and is the left
/// wire
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum WireData {
    /// Left Wire of n'th gate
    Left(usize),
    /// Right Wire of n'th gate
    Right(usize),
    /// Output Wire of n'th gate
    Output(usize),
    /// Fourth Wire of n'th gate
    Fourth(usize),
}

/// Allocated witness in the constraint system.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Witness {
    index: usize,
}

impl Default for Witness {
    fn default() -> Self {
        crate::composer::Composer::ZERO
    }
}

impl Witness {
    /// A `0` witness representation.
    pub const ZERO: Witness = Witness::new(0);

    /// A `1` witness representation.
    pub const ONE: Witness = Witness::new(1);

    /// Generate a new [`Witness`]
    pub(crate) const fn new(index: usize) -> Self {
        Self { index }
    }

    /// Index of the allocated witness in the composer
    pub const fn index(&self) -> usize {
        self.index
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for Witness {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_constants_and_default_are_consistent() {
        assert_eq!(Witness::ZERO.index(), 0);
        assert_eq!(Witness::ONE.index(), 1);

        // `Default` is implemented as `Witness::ZERO`.
        assert_eq!(Witness::default(), Witness::ZERO);
    }

    #[test]
    fn wire_data_variants_are_distinct_and_debuggable() {
        let a = WireData::Left(0);
        let b = WireData::Right(0);
        let c = WireData::Output(0);
        let d = WireData::Fourth(0);

        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(c, d);

        // Debug fmt should not panic.
        let _ = format!("{a:?}{b:?}{c:?}{d:?}");

        // Pattern match to make sure we can extract indices.
        match a {
            WireData::Left(i) => assert_eq!(i, 0),
            _ => panic!("expected Left"),
        }
    }
}
