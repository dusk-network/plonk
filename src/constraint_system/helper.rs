// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::StandardComposer;
use crate::commitment_scheme::kzg10::PublicParameters;
use crate::error::Error;
use crate::plookup::PlookupTable4Arity;
use crate::proof_system::{Prover, Verifier};
use dusk_bls12_381::BlsScalar;
use rand_core::OsRng;

/// Adds dummy constraints using arithmetic gates
pub(crate) fn dummy_gadget(n: usize, composer: &mut StandardComposer) {
    let one = BlsScalar::one();

    let var_one = composer.add_input(one);

    for _ in 0..n {
        composer.big_add(
            (BlsScalar::one(), var_one),
            (BlsScalar::one(), var_one),
            None,
            BlsScalar::zero(),
            None,
        );
    }
}

/// Adds dummy constraints using arithmetic gates
pub(crate) fn dummy_gadget_plookup(n: usize, composer: &mut StandardComposer) {
    let one = BlsScalar::one();

    let var_one = composer.add_input(one);

    for _ in 0..n {
        composer.big_add(
            (BlsScalar::one(), var_one),
            (BlsScalar::one(), var_one),
            None,
            BlsScalar::zero(),
            Some(BlsScalar::zero()),
        );
    }
}

/// Takes a generic gadget function with no auxillary input and
/// tests whether it passes an end-to-end test
pub(crate) fn gadget_tester(
    gadget: fn(composer: &mut StandardComposer),
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
        gadget(&mut prover.mut_cs());

        // Commit Key
        let (ck, _) = public_parameters
            .trim(2 * prover.cs.circuit_size().next_power_of_two())?;

        // Preprocess circuit
        prover.preprocess(&ck)?;

        // Once the prove method is called, the public inputs are cleared
        // So pre-fetch these before calling Prove
        let public_inputs = prover.cs.construct_dense_pi_vec();

        // Compute Proof
        (prover.prove(&ck)?, public_inputs)
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
        .trim(verifier.cs.circuit_size().next_power_of_two())?;

    // Preprocess circuit
    verifier.preprocess(&ck)?;

    // Verify proof
    verifier.verify(&proof, &vk, &public_inputs)
}

/// Takes a generic gadget function with no auxillary input and
/// tests whether it passes an end-to-end test. If using a lookup table,
/// all plookup gates must correspond to rows in lookup_table
pub(crate) fn gadget_plookup_tester(
    gadget: fn(composer: &mut StandardComposer),
    n: usize,
    lookup_table: PlookupTable4Arity,
) -> Result<(), Error> {
    // Common View
    let public_parameters = PublicParameters::setup(2 * n, &mut OsRng)?;
    // Provers View
    let (proof, public_inputs) = {
        // Create a prover struct
        let mut prover = Prover::new(b"demo");

        // Add lookup table to the composer
        prover.mut_cs().append_lookup_table(&lookup_table);

        // Additionally key the transcript
        prover.key_transcript(b"key", b"additional seed information");

        // Add gadgets
        gadget(&mut prover.mut_cs());

        // Commit Key
        let (ck, _) = public_parameters
            .trim(2 * prover.cs.circuit_size().next_power_of_two())?;

        // Preprocess circuit
        prover.preprocess(&ck)?;

        // Once the prove method is called, the public inputs are cleared
        // So pre-fetch these before calling Prove
        let public_inputs = prover.cs.construct_dense_pi_vec();

        // Compute Proof
        (prover.prove(&ck)?, public_inputs)
    };
    // Verifiers view
    //
    // Create a Verifier object
    let mut verifier = Verifier::new(b"demo");

    // Add lookup table to the composer
    verifier.mut_cs().append_lookup_table(&lookup_table);

    // Additionally key the transcript
    verifier.key_transcript(b"key", b"additional seed information");

    // Add gadgets
    gadget(&mut verifier.mut_cs());

    // Compute Commit and Verifier Key
    let (ck, vk) = public_parameters
        .trim(verifier.cs.circuit_size().next_power_of_two())?;

    // Preprocess circuit
    verifier.preprocess(&ck)?;

    // Verify proof
    verifier.verify(&proof, &vk, &public_inputs)
}
