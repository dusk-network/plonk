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
fn range() {
    #[derive(Default)]
    pub struct TestCircuit<const BIT_PAIRS: usize> {
        a: BlsScalar,
    }

    impl<const BIT_PAIRS: usize> TestCircuit<BIT_PAIRS> {
        pub fn new(a: BlsScalar) -> Self {
            Self { a }
        }
    }

    impl<const BIT_PAIRS: usize> Circuit for TestCircuit<BIT_PAIRS> {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);

            composer.component_range::<BIT_PAIRS>(w_a);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_range";
    let rng = &mut StdRng::seed_from_u64(0xb1eeb);
    let capacity = 1 << 6;
    let pp = PublicParameters::setup(capacity, rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit<0>>(&pp, label)
        .expect("Circuit should compile");

    // public input to be used by all tests
    let pi = vec![];

    // Test bits = 0
    //
    // Test default works:
    // 0 < 2^0
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::<0>::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // 1 < 2^0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let circuit: TestCircuit<0> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test:
    // random !< 2^0
    let msg = "Unsatisfied circuit should fail";
    let a = BlsScalar::random(rng);
    assert!(a != BlsScalar::zero());
    let circuit: TestCircuit<0> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test bits = 2
    //
    // Compile new circuit descriptions for the prover and verifier
    const BIT_PAIRS_1: usize = 1;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BIT_PAIRS_1>>(&pp, label)
            .expect("Circuit should compile");

    // Test:
    // 1 < 2^2
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::one();
    let circuit: TestCircuit<BIT_PAIRS_1> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test fails:
    // 4 !< 2^2
    let msg = "Proof creation of an unsatisfied circuit should fail";
    let a = BlsScalar::from(4);
    let circuit: TestCircuit<BIT_PAIRS_1> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test bits = 74
    //
    // Compile new circuit descriptions for the prover and verifier
    const BIT_PAIRS_37: usize = 37;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BIT_PAIRS_37>>(&pp, label)
            .expect("Circuit should compile");

    // Test:
    // 2^73 < 2^74
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::pow_of_2(73);
    let circuit: TestCircuit<BIT_PAIRS_37> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // 2^74 - 1 < 2^74
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::pow_of_2(74) - BlsScalar::one();
    let circuit: TestCircuit<BIT_PAIRS_37> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test fails:
    // 2^74 !< 2^74
    let msg = "Proof creation of an unsatisfied circuit should fail";
    let a = BlsScalar::pow_of_2(74);
    let circuit: TestCircuit<BIT_PAIRS_37> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test bits = 256
    //
    // Compile new circuit descriptions for the prover and verifier
    const BIT_PAIRS_128: usize = 128;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BIT_PAIRS_128>>(&pp, label)
            .expect("Circuit should compile");

    // Test:
    // 2^255 < 2^256
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::pow_of_2(255);
    let circuit: TestCircuit<BIT_PAIRS_128> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // -bls(1) < 2^256
    let msg = "Verification of a satisfied circuit should pass";
    let a = -BlsScalar::one();
    let circuit: TestCircuit<BIT_PAIRS_128> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);
}
