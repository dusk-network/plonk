// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::compress::CompressedCircuit;
use crate::prelude::{Composer, Error};

/// Circuit implementation that can be proved by a Composer
///
/// [`Compiler::compile`] and [`Circuit::compress`] build the circuit from its
/// [`Default`] value. A circuit without one is compiled from an instance with
/// [`Compiler::compile_with_circuit`].
///
/// [`Compiler::compile`]: crate::prelude::Compiler::compile
/// [`Compiler::compile_with_circuit`]:
/// crate::prelude::Compiler::compile_with_circuit
pub trait Circuit {
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
    /// crate::prelude::Compiler::compile_with_compressed
    #[cfg(feature = "alloc")]
    fn compress() -> Result<Vec<u8>, Error>
    where
        Self: Default,
    {
        let mut composer = Composer::initialized();
        Self::default().circuit(&mut composer)?;

        let hades_optimization = true;
        Ok(CompressedCircuit::from_composer(
            hades_optimization,
            composer,
        ))
    }
}
