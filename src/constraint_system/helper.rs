// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::StandardComposer;
use crate::commitment_scheme::kzg10::PublicParameters;
use crate::proof_system::{Prover, Verifier};
use anyhow::{anyhow, Result};
use dusk_bls12_381::BlsScalar;

/// Adds dummy constraints using arithmetic gates
pub(crate) fn dummy_gadget(n: usize, composer: &mut StandardComposer) {
    let one = BlsScalar::one();

    let var_one = composer.add_input(one);

    for _ in 0..n {
        composer.big_add(
            var_one.into(),
            var_one.into(),
            None,
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }
}

/// Takes a generic gadget function with no auxillary input and
/// tests whether it passes an end-to-end test
pub(crate) fn gadget_tester(gadget: fn(composer: &mut StandardComposer), n: usize) -> Result<()> {
    // Common View
    let public_parameters =
        PublicParameters::setup(2 * n, &mut rand::thread_rng()).map_err(|e| anyhow!("{:?}", e))?;
    // Provers View
    let (proof, public_inputs) = {
        // Create a prover struct
        let mut prover = Prover::new(b"demo");

        // Additionally key the transcript
        prover.key_transcript(b"key", b"additional seed information");

        // Add gadgets
        gadget(&mut prover.mut_cs());

        // Commit Key
        let (ck, _) = public_parameters
            .trim(2 * prover.cs.circuit_size().next_power_of_two())
            .map_err(|e| anyhow!("{:?}", e))?;

        // Preprocess circuit
        prover.preprocess(&ck).map_err(|e| anyhow!("{:?}", e))?;

        // Once the prove method is called, the public inputs are cleared
        // So pre-fetch these before calling Prove
        let public_inputs = prover.cs.public_inputs.clone();

        // Compute Proof
        (
            prover.prove(&ck).map_err(|e| anyhow!("{:?}", e))?,
            public_inputs,
        )
    };
    // Verifiers view
    //
    // Create a Verifier object
    let mut verifier = Verifier::new(b"demo");

    // Additionally key the transcript
    verifier.key_transcript(b"key", b"additional seed information");

    // Add gadgets
    gadget(&mut verifier.mut_cs());

    // Compute Commit and Verifier Key
    let (ck, vk) = public_parameters
        .trim(verifier.cs.circuit_size().next_power_of_two())
        .map_err(|e| anyhow!("{:?}", e))?;

    // Preprocess circuit
    verifier.preprocess(&ck).map_err(|e| anyhow!("{:?}", e))?;

    // Verify proof
    verifier
        .verify(&proof, &vk, &public_inputs)
        .map_err(|e| anyhow!("{:?}", e))
}
