// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use ff::Field;
use rand::SeedableRng;
use rand::rngs::StdRng;

mod common;
use common::{check_satisfied_circuit, check_unsatisfied_circuit};

#[test]
fn range() {
    #[derive(Default)]
    pub struct TestCircuit<const BITS: usize> {
        a: BlsScalar,
    }

    impl<const BITS: usize> TestCircuit<BITS> {
        pub fn new(a: BlsScalar) -> Self {
            Self { a }
        }
    }

    impl<const BITS: usize> Circuit for TestCircuit<BITS> {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_a = composer.append_witness(self.a);

            composer.component_range_bits::<BITS>(w_a);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_range_bits";
    let mut rng = StdRng::seed_from_u64(0xb1eeb);
    let capacity = 1 << 6;
    let pp = PublicParameters::setup(capacity, &mut rng)
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
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test:
    // 1 < 2^0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let circuit: TestCircuit<0> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test:
    // random !< 2^0
    let msg = "Unsatisfied circuit should fail";
    let a = BlsScalar::random(&mut rng);
    assert!(a != BlsScalar::zero());
    let circuit: TestCircuit<0> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test bits = 2
    //
    // Compile new circuit descriptions for the prover and verifier
    const BITS_2: usize = 2;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BITS_2>>(&pp, label)
            .expect("Circuit should compile");

    // Test:
    // 1 < 2^2
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::one();
    let circuit: TestCircuit<BITS_2> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test fails:
    // 4 !< 2^2
    let msg = "Proof creation of an unsatisfied circuit should fail";
    let a = BlsScalar::from(4);
    let circuit: TestCircuit<BITS_2> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test bits = 7 (odd width)
    //
    // Compile new circuit descriptions for the prover and verifier
    const BITS_7: usize = 7;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BITS_7>>(&pp, label)
            .expect("Circuit should compile");

    // Test:
    // 2^7 - 1 < 2^7
    let msg = "Verification of a satisfied odd-width circuit should pass";
    let a = BlsScalar::from(127);
    let circuit: TestCircuit<BITS_7> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test fails:
    // 2^7 !< 2^7
    let msg = "Proof creation of an unsatisfied odd-width circuit should fail";
    let a = BlsScalar::from(128);
    let circuit: TestCircuit<BITS_7> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test bits = 74
    //
    // Compile new circuit descriptions for the prover and verifier
    const BITS_74: usize = 74;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BITS_74>>(&pp, label)
            .expect("Circuit should compile");

    // Test:
    // 2^73 < 2^74
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::pow_of_2(73);
    let circuit: TestCircuit<BITS_74> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test:
    // 2^74 - 1 < 2^74
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::pow_of_2(74) - BlsScalar::one();
    let circuit: TestCircuit<BITS_74> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test fails:
    // 2^74 !< 2^74
    let msg = "Proof creation of an unsatisfied circuit should fail";
    let a = BlsScalar::pow_of_2(74);
    let circuit: TestCircuit<BITS_74> = TestCircuit::new(a);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test bits = 256
    //
    // Compile new circuit descriptions for the prover and verifier
    const BITS_256: usize = 256;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BITS_256>>(&pp, label)
            .expect("Circuit should compile");

    // Test:
    // 2^255 < 2^256
    let msg = "Verification of a satisfied circuit should pass";
    let a = BlsScalar::pow_of_2(255);
    let circuit: TestCircuit<BITS_256> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test:
    // -bls(1) < 2^256
    let msg = "Verification of a satisfied circuit should pass";
    let a = -BlsScalar::one();
    let circuit: TestCircuit<BITS_256> = TestCircuit::new(a);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);
}
