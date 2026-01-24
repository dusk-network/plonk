// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

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
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let sum = self.witnesses.iter().fold(Composer::ZERO, |acc, scalar| {
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

    // compiling the default version of TestSize circuit, with only one gate in
    // addition to the 4 dummy gates
    let (prover, _verifier) = Compiler::compile::<TestSize>(&pp, LABEL)
        .expect("It should be possible to compile the prover and verifier");

    // Create circuit with more gates
    let witnesses: Vec<BlsScalar> = [BlsScalar::one(); 4].into();
    let sum = witnesses.iter().sum();
    let circuit = TestSize::new(witnesses, sum);
    let result = prover.prove(rng, &circuit);
    let empty_circuit_size = Composer::initialized().constraints();
    assert!(result.is_err_and(|e| e
        == Error::InvalidCircuitSize(
            empty_circuit_size + 5,
            empty_circuit_size + 1
        )));
}
