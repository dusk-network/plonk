// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

mod common;
use common::{check_satisfied_circuit, check_unsatisfied_circuit};

#[test]
fn component_boolean() {
    pub struct TestCircuit {
        bit: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(bit: BlsScalar) -> Self {
            Self { bit }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::new(0u64.into())
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_bit = composer.append_witness(self.bit);

            composer.component_boolean(w_bit);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_boolean";
    let rng = &mut StdRng::seed_from_u64(0xfade);
    let capacity = 1 << 4;
    let pp = PublicParameters::setup(capacity, rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

    // public inputs to be used by all tests
    let pi = vec![];

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works
    let msg = "Circuit with bit = 1 should pass";
    let bit = BlsScalar::one();
    let circuit = TestCircuit::new(bit);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works
    let msg = "Circuit with bit = 0 should pass";
    let bit = BlsScalar::zero();
    let circuit = TestCircuit::new(bit);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test -zero works
    let msg = "Circuit with bit = -0 should pass";
    let bit = -BlsScalar::zero();
    let circuit = TestCircuit::new(bit);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test -one fails
    let msg = "Circuit with bit = -1 shouldn't pass";
    let bit = -BlsScalar::one();
    let circuit = TestCircuit::new(bit);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg = "Circuit with bit = -1 shouldn't pass";
    let bit = BlsScalar::random(rng);
    let circuit = TestCircuit::new(bit);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}
