// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

const CAPACITY: usize = 1 << 4;
const LABEL: &[u8] = b"check_public_inputs";

#[derive(Default)]
pub struct TestSize {
    witnesses: Vec<BlsScalar>,
    sum: BlsScalar,
}

impl TestSize {
    pub fn new(witnesses: Vec<BlsScalar>, sum: BlsScalar) -> Self {
        Self { witnesses, sum }
    }
}

impl Circuit for TestSize {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        let sum = self.witnesses.iter().fold(C::ZERO, |acc, scalar| {
            let w = composer.append_witness(*scalar);
            let constraint = Constraint::new().left(1).a(acc).right(1).b(w);
            composer.gate_add(constraint)
        });

        let expected_sum = composer.append_witness(self.sum);
        composer.assert_equal(sum, expected_sum);

        Ok(())
    }
}

#[test]
fn size() {
    let rng = &mut StdRng::seed_from_u64(0x10b);
    let pp = PublicParameters::setup(CAPACITY, rng)
        .expect("Creation of public parameter shouldn't fail");

    // compiling the default version of TestSize, which only one gate: sum = 0
    let (prover, _verifier) = Compiler::compile::<TestSize>(&pp, LABEL)
        .expect("It should be possible to compile the prover and verifier");

    // Create circuit with more gates
    let pi: Vec<BlsScalar> = [BlsScalar::one(); 5].into();
    let sum = pi.iter().sum();
    let circuit = TestSize::new(pi, sum);
    let result = prover.prove(rng, &circuit);
    assert_eq!(
        result,
        Err(Error::InvalidCircuitSize),
        "proof creation for different sized circuit shouldn't be possible"
    );
}
