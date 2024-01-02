// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::prelude::{Composer, Error};

use super::compress::CompressedCircuit;

/// Circuit implementation that can be proved by a Composer
///
/// The default implementation will be used to generate the proving arguments.
pub trait Circuit: Default {
    /// Circuit definition
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error>;

    /// Returns the size of the circuit.
    fn size(&self) -> usize {
        let mut composer = Composer::initialized();
        match self.circuit(&mut composer) {
            Ok(_) => composer.constraints(),
            Err(_) => 0,
        }
    }

    /// Return a bytes representation of a compressed circuit, capable of
    /// being compiled into its prover and verifier instances with
    /// [`Compiler::compile_with_compressed`].
    ///
    /// [`Compiler::compile_with_compressed`]:
    /// [`crate::prelude::Compiler::compile_with_compressed`]
    #[cfg(feature = "alloc")]
    fn compress() -> Result<Vec<u8>, Error> {
        let mut composer = Composer::initialized();
        Self::default().circuit(&mut composer)?;

        let hades_optimization = true;
        Ok(CompressedCircuit::from_composer(
            hades_optimization,
            composer,
        ))
    }
}
