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

/// Witness data indexed in a [`TurboComposer`](super::TurboComposer) instance
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Witness {
    index: usize,
}

impl Witness {
    /// Generate a new [`Witness`]
    pub(crate) const fn new(index: usize) -> Self {
        Self { index }
    }

    /// Index of the allocated witness in the composer
    pub const fn index(&self) -> usize {
        self.index
    }
}
