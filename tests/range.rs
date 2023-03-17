// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

mod common;
use common::{check_satisfied_circuit, check_unsatisfied_circuit, setup};

#[test]
fn range() {
    #[derive(Default)]
    pub struct TestCircuit {
        a: BlsScalar,
        bits: usize,
    }

    impl TestCircuit {
        pub fn new(a: BlsScalar, bits: usize) -> Self {
            Self { a, bits }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);

            composer.component_range(w_a, self.bits);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_range";
    let rng = &mut StdRng::seed_from_u64(0xb1eeb);
    let capacity = 1 << 6;
    let (prover, verifier) =
        setup(capacity, rng, label, &TestCircuit::default());

    // public input to be used by all tests
    let pi = vec![];

    // Test bits = 0
    //
    // Test default works:
    // 0 < 2^0
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    /* FIXME #746:
    * nothing can be encoded in zero bits so when bits = 0, all witnesses
    * (except zero itself maybe) should fail
    // Test:
    // 1 < 2^0
    let msg = "Verification of satisfied circuit should pass";
    let bits = 0;
    let a = BlsScalar::one();
    let circuit = TestCircuit::new(a, bits);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test:
    // random !< 2^0
    let msg = "Unsatisfied circuit should fail";
    let a = BlsScalar::random(rng);
    assert!(a != BlsScalar::zero());
    let circuit = TestCircuit::new(a, bits);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
    */

    // Test bits = 2
    //
    // Compile new circuit descriptions for the prover and verifier
    let bits = 2;
    let a = BlsScalar::one();
    let circuit = TestCircuit::new(a, bits);
    let (prover, verifier) = setup(capacity, rng, label, &circuit);

    // Test:
    // 1 < 2^2
    let msg = "Verification of a satisfied circuit should pass";
    let circuit = TestCircuit::new(a, bits);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test fails:
    // 4 !< 2^2
    let msg = "Proof creation of an unsatisfied circuit should fail";
    let a = BlsScalar::from(4);
    let circuit = TestCircuit::new(a, bits);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test bits = 4
    //
    // Compile new circuit descriptions for the prover and verifier
    let bits = 4;
    let a = BlsScalar::from(15);
    let circuit = TestCircuit::new(a, bits);
    let (prover, verifier) = setup(capacity, rng, label, &circuit);

    // Test:
    // 15 < 2^4
    let msg = "Verification of a satisfied circuit should pass";
    let circuit = TestCircuit::new(a, bits);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test fails:
    // 16 !< 2^4
    let msg = "Proof creation of an unsatisfied circuit should fail";
    let a = BlsScalar::from(16);
    let circuit = TestCircuit::new(a, bits);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test bits = 74
    //
    // Compile new circuit descriptions for the prover and verifier
    let bits = 74;
    let a = BlsScalar::pow_of_2(73);
    let circuit = TestCircuit::new(a, bits);
    let (prover, verifier) = setup(capacity, rng, label, &circuit);

    // Test:
    // 2^73 < 2^74
    let msg = "Verification of a satisfied circuit should pass";
    let circuit = TestCircuit::new(a, bits);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // 2^74 - 1 < 2^74
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::pow_of_2(74) - BlsScalar::one();
    let circuit = TestCircuit::new(a, bits);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test fails:
    // 2^74 !< 2^74
    let msg = "Proof creation of an unsatisfied circuit should fail";
    let a = BlsScalar::pow_of_2(74);
    let circuit = TestCircuit::new(a, bits);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test bits = 256
    //
    // Compile new circuit descriptions for the prover and verifier
    let bits = 256;
    let a = BlsScalar::pow_of_2(255);
    let circuit = TestCircuit::new(a, bits);
    let (prover, verifier) = setup(capacity, rng, label, &circuit);

    // Test:
    // 2^255 < 2^256
    let msg = "Verification of a satisfied circuit should pass";
    let circuit = TestCircuit::new(a, bits);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // -bls(1) < 2^256
    let msg = "Verification of a satisfied circuit should pass";
    let a = -BlsScalar::one();
    let circuit = TestCircuit::new(a, bits);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);
}
