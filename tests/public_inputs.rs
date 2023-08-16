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
pub struct TestPI {
    public: Vec<BlsScalar>,
    sum: BlsScalar,
}

impl TestPI {
    pub fn new(public: Vec<BlsScalar>, sum: BlsScalar) -> Self {
        Self { public, sum }
    }
}

impl Circuit for TestPI {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        // this circuit will always have the same amount of gates but different
        // amount of public inputs, depending on the struct data
        let mut sum = C::ZERO;
        for i in 0..2 {
            let constraint = match i < self.public.len() {
                true => Constraint::new()
                    .left(1)
                    .a(sum)
                    .right(1)
                    .b(C::ONE)
                    .public(self.public[i]),
                false => Constraint::new().left(1).a(sum).right(1).b(C::ONE),
            };
            sum = composer.gate_add(constraint);
        }
        let expected_sum = composer.append_witness(self.sum);
        composer.assert_equal(sum, expected_sum);

        Ok(())
    }
}

#[ignore = "test for issue #762"]
#[test]
fn public_inputs() {
    let rng = &mut StdRng::seed_from_u64(0x10b);
    let pp = PublicParameters::setup(CAPACITY, rng)
        .expect("Creation of public parameter shouldn't fail");

    // compiling the default version of TestPI, which has no pi
    let (prover, _verifier) = Compiler::compile::<TestPI>(&pp, LABEL)
        .expect("It should be possible to compile the prover and verifier");

    // Create circuit with public inputs
    let pi: Vec<BlsScalar> = [BlsScalar::one(); 2].into();
    let sum = BlsScalar::from(4);
    let circuit = TestPI::new(pi, sum);
    let result = prover.prove(rng, &circuit);
    assert!(
        result.is_err(),
        "proof creation for circuit diferrent from  circuit description shouldn't be possible"
    );
}
