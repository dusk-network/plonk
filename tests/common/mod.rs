// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::{CryptoRng, RngCore};

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
    let (proof, pi_circuit) = prover
        .prove(rng, circuit)
        .expect("Prover for valid circuit shouldn't fail");

    assert_eq!(*pi_expected, pi_circuit);

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
    let (proof, pi_circuit) = prover
        .prove(rng, circuit)
        .expect("Prover for valid circuit shouldn't fail");

    assert_eq!(*pi_expected, pi_circuit);

    verifier.verify(&proof, &pi_expected).expect_err(msg);
}

// Check that proof creation of an unsatisfied circuit fails
// This is also the case when the constants appended to the circuit does not
// match the ones from the circuit description
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
