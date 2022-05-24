// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::TurboComposer;
use crate::commitment_scheme::PublicParameters;
use crate::constraint_system::Constraint;
use crate::error::Error;
use crate::proof_system::{Prover, Verifier};
use dusk_bls12_381::BlsScalar;
use rand_core::OsRng;

/// Adds dummy gates using arithmetic gates
pub(crate) fn dummy_gadget(n: usize, composer: &mut TurboComposer) {
    let one = BlsScalar::one();
    let one = composer.append_witness(one);

    for _ in 0..n {
        // FIXME dummy gates with zeroed selectors doesn't make sense
        let constraint = Constraint::new().left(1).right(1).a(one).b(one);

        composer.gate_add(constraint);
    }
}

/// Takes a generic gadget function with no auxillary input and
/// tests whether it passes an end-to-end test
pub(crate) fn gadget_tester(
    gadget: fn(composer: &mut TurboComposer),
    n: usize,
) -> Result<(), Error> {
    // Common View
    let public_parameters = PublicParameters::setup(2 * n, &mut OsRng)?;
    // Provers View
    let (proof, public_inputs) = {
        // Create a prover struct
        let mut prover = Prover::new(b"demo");

        // Additionally key the transcript
        prover.key_transcript(b"key", b"additional seed information");

        // Add gadgets
        gadget(&mut prover.composer_mut());

        // Commit Key
        let (ck, _) = public_parameters
            .trim(2 * prover.cs.gates().next_power_of_two())?;

        // Preprocess circuit
        prover.preprocess(&ck)?;

        // Once the prove method is called, the public inputs are cleared
        // So pre-fetch these before calling Prove
        let public_inputs = prover.cs.to_dense_public_inputs();

        // Compute Proof
        (prover.prove(&ck, &mut OsRng)?, public_inputs)
    };
    // Verifiers view
    //
    // Create a Verifier object
    let mut verifier = Verifier::new(b"demo");

    // Additionally key the transcript
    verifier.key_transcript(b"key", b"additional seed information");

    // Add gadgets
    gadget(&mut verifier.composer_mut());

    // Compute Commit and Verifier Key
    let (ck, vk) =
        public_parameters.trim(verifier.cs.gates().next_power_of_two())?;

    // Preprocess circuit
    verifier.preprocess(&ck)?;

    let pi_indexes = verifier.composer_mut().public_input_indexes();

    // Verify proof
    verifier.verify(&proof, &vk, &public_inputs, &pi_indexes)
}
