// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PublicInputPositions;

/// This is an utility trait designed to further constrain the [`Circuit`] trait
/// to hold a [`PublicInputPositions`].
pub trait PiPositionsHolder {
    /// Return a mutable reference to the Public Input positions storage of the struct.
    fn get_mut_pi_positions(&mut self) -> &mut PublicInputPositions;

    /// Push a new Public Input position into the storage of the struct.
    fn push_pi(&mut self, pos: usize) {
        self.get_mut_pi_positions().0.push(pos)
    }
}
