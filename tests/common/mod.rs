// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::{CryptoRng, RngCore};

// Create the circuit description for both the prover and the verifier,
// the `capacity` is a power of two and larger than the amount of gates in `C`
pub(crate) fn setup<C, R>(
    capacity: usize,
    rng: &mut R,
    label: &[u8],
    circuit: &C,
) -> (Prover, Verifier)
where
    C: Circuit,
    R: RngCore + CryptoRng,
{
    let pp = PublicParameters::setup(capacity, rng)
        .expect("Creation of public parameter shouldn't fail");
    Compiler::compile_with_circuit(&pp, label, circuit)
        .expect("It should be possible to compile the prover and verifier")
}

// Check that proof creation and verification of a satisfied circuit passes
// and that the public inputs are as expected
pub(crate) fn check_satisfied_circuit<C, R>(
    prover: &Prover,
    verifier: &Verifier,
    pi_expected: &Vec<BlsScalar>,
    circuit: &C,
    rng: &mut R,
    msg: &str,
) where
    C: Circuit,
    R: RngCore + CryptoRng,
{
    let (proof, _pi_circuit) = prover
        .prove(rng, circuit)
        .expect("Prover for valid circuit shouldn't fail");

    verifier.verify(&proof, &pi_expected).expect(msg);
}

// Check that proof creation and verification of a satisfied circuit fails
// when the public inputs from the test circuit does not match the ones from
// the verifier circuit description
// As this is a very specific test case, this function will not be used by all
// tests.
#[allow(dead_code)]
pub(crate) fn check_satisfied_circuit_fails<C, R>(
    prover: &Prover,
    verifier: &Verifier,
    pi_expected: &Vec<BlsScalar>,
    circuit: &C,
    rng: &mut R,
    msg: &str,
) where
    C: Circuit,
    R: RngCore + CryptoRng,
{
    let (proof, _pi_circuit) = prover
        .prove(rng, circuit)
        .expect("Prover for valid circuit shouldn't fail");

    verifier.verify(&proof, &pi_expected).expect_err(msg);
}

// Check that proof creation of an unsatisfied circuit fails
// This is also the case when the constants appended to the circuit does not
// match the ones from the circuit description
#[allow(dead_code)]
pub(crate) fn check_unsatisfied_circuit<C, R>(
    prover: &Prover,
    circuit: &C,
    rng: &mut R,
    msg: &str,
) where
    C: Circuit,
    R: RngCore + CryptoRng,
{
    prover.prove(rng, circuit).expect_err(msg);
}
