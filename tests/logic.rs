// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::cmp;
use dusk_plonk::prelude::*;
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

mod common;
use common::{check_satisfied_circuit, check_unsatisfied_circuit};

#[test]
fn append_logic_and() {
    #[derive(Default)]
    pub struct TestCircuit<const BIT_PAIRS: usize> {
        a: BlsScalar,
        b: BlsScalar,
        result: BlsScalar,
    }

    impl<const BIT_PAIRS: usize> TestCircuit<BIT_PAIRS> {
        pub fn new(a: BlsScalar, b: BlsScalar) -> Self {
            let bits = cmp::min(BIT_PAIRS * 2, 256);
            let bit_mask = BlsScalar::pow_of_2(bits as u64) - BlsScalar::one();

            // BlsScalar are max 255 bits long which means that a bit_mask with
            // more than 255 bits will be overflowing and therefore incorrect
            let result = match bits <= 255 {
                true => a & b & bit_mask,
                false => a & b,
            };

            Self { a, b, result }
        }
    }

    impl<const BIT_PAIRS: usize> Circuit for TestCircuit<BIT_PAIRS> {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_witness(self.b);
            let w_result = composer.append_witness(self.result);

            let circuit_result =
                composer.append_logic_and::<BIT_PAIRS>(w_a, w_b);

            composer.assert_equal(w_result, circuit_result);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier with the
    // default circuit
    let label = b"append_logic_and";
    let mut rng = StdRng::seed_from_u64(0x1ead);
    let capacity = 1 << 8;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit<0>>(&pp, label)
        .expect("Circuit should compile");

    // Common public input vector to be used by all tests
    let pi = vec![];

    // Test with bits = 0
    //
    // Test default works
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::<0>::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test comparing 0 bits is always zero
    let msg = "Circuit verification of satisfied circuit should pass";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let circuit = TestCircuit::<0> {
        a,
        b,
        result: BlsScalar::zero(),
    };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test with bits = 32
    //
    // Create new prover and verifier circuit descriptions
    const BIT_PAIRS_16: usize = 16;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BIT_PAIRS_16>>(&pp, label)
            .expect("Circuit should compile");

    // Test sanity:
    let a = BlsScalar::from(0x0f0f_0ff0_0f0f_0ff0);
    let b = BlsScalar::from(0xffff_0000_0000_ffff);
    let result = BlsScalar::from(0x0000_0ff0);
    let circuit: TestCircuit<BIT_PAIRS_16> = TestCircuit { a, b, result };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test random works:
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let circuit: TestCircuit<BIT_PAIRS_16> = TestCircuit::new(a, b);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test invalid circuit fails
    let msg = "Proof creation of unsatisfied circuit should fail";
    let bit_mask =
        BlsScalar::pow_of_2(BIT_PAIRS_16 as u64 * 2) - BlsScalar::one();
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let right_result = a & b & bit_mask;
    let c = BlsScalar::random(&mut rng);
    let wrong_result = a & c & bit_mask;
    assert_ne!(right_result, wrong_result);
    let circuit_unsatisfied: TestCircuit<BIT_PAIRS_16> = TestCircuit {
        a,
        b,
        result: wrong_result,
    };
    check_unsatisfied_circuit(&prover, &circuit_unsatisfied, &mut rng, &msg);
    // sanity check
    let circuit_satisfied: TestCircuit<BIT_PAIRS_16> = TestCircuit {
        a,
        b,
        result: right_result,
    };
    check_satisfied_circuit(
        &prover,
        &verifier,
        &pi,
        &circuit_satisfied,
        &mut rng,
        &"Sanity check should pass",
    );

    // Test with bits = 256
    //
    // Create new circuit description for the prover and verifier
    const BIT_PAIRS_128: usize = 128;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BIT_PAIRS_128>>(&pp, label)
            .expect("Circuit should compile");

    // Test sanity:
    let a = -BlsScalar::one();
    let b = -BlsScalar::one();
    let result = -BlsScalar::one();
    let circuit: TestCircuit<BIT_PAIRS_128> = TestCircuit { a, b, result };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test random works:
    let msg = "Circuit verification with random values should pass";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let circuit: TestCircuit<BIT_PAIRS_128> = TestCircuit::new(a, b);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test invalid circuit fails
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let right_result = a & b;
    let c = BlsScalar::random(&mut rng);
    let wrong_result = a & c;
    assert_ne!(right_result, wrong_result);
    let circuit: TestCircuit<BIT_PAIRS_128> = TestCircuit {
        a,
        b,
        result: wrong_result,
    };
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);
    // sanity check
    let circuit_satisfied: TestCircuit<BIT_PAIRS_128> = TestCircuit {
        a,
        b,
        result: right_result,
    };
    check_satisfied_circuit(
        &prover,
        &verifier,
        &pi,
        &circuit_satisfied,
        &mut rng,
        &"Sanity check should pass",
    );
}

#[test]
fn append_logic_xor() {
    #[derive(Default)]
    pub struct TestCircuit<const BIT_PAIRS: usize> {
        a: BlsScalar,
        b: BlsScalar,
        result: BlsScalar,
    }

    impl<const BIT_PAIRS: usize> TestCircuit<BIT_PAIRS> {
        pub fn new(a: BlsScalar, b: BlsScalar) -> Self {
            let bits = cmp::min(BIT_PAIRS * 2, 256);
            let bit_mask = BlsScalar::pow_of_2(bits as u64) - BlsScalar::one();

            // BlsScalar are max 255 bits long so a bit_mask with more than 255
            // bits will be overflowing and incorrect
            let result = match bits < 256 {
                true => (a ^ b) & bit_mask,
                false => a ^ b,
            };

            Self { a, b, result }
        }
    }

    impl<const BIT_PAIRS: usize> Circuit for TestCircuit<BIT_PAIRS> {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_witness(self.b);
            let w_result = composer.append_witness(self.result);

            let circuit_result =
                composer.append_logic_xor::<BIT_PAIRS>(w_a, w_b);

            composer.assert_equal(w_result, circuit_result);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"append_logic_xor";
    let mut rng = StdRng::seed_from_u64(0xdea1);
    let capacity = 1 << 8;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit<0>>(&pp, label)
        .expect("Circuit should compile");

    // Common values to be used by all tests
    let pi = vec![];

    // Test with bits = 0
    //
    // Test default works
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::<0>::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test comparing 0 bits is always zero
    let msg = "Circuit verification of satisfied circuit should pass";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let circuit: TestCircuit<0> = TestCircuit {
        a,
        b,
        result: BlsScalar::zero(),
    };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test with bits = 32
    //
    // Create new prover and verifier circuit descriptions
    const BIT_PAIRS_16: usize = 16;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BIT_PAIRS_16>>(&pp, label)
            .expect("Circuit should compile");

    // Test sanity:
    let a = BlsScalar::from(0x0f0f_0ff0_0f0f_0ff0);
    let b = BlsScalar::from(0xffff_0000_0000_ffff);
    let result = BlsScalar::from(0x0f0f_f00f);
    let circuit: TestCircuit<BIT_PAIRS_16> = TestCircuit { a, b, result };

    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test random works:
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let circuit: TestCircuit<BIT_PAIRS_16> = TestCircuit::new(a, b);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test invalid circuit fails
    let msg = "Proof creation of unsatisfied circuit should fail";
    let bit_mask =
        BlsScalar::pow_of_2(BIT_PAIRS_16 as u64 * 2) - BlsScalar::one();
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let right_result = (a ^ b) & bit_mask;
    let c = BlsScalar::random(&mut rng);
    let wrong_result = (a ^ c) & bit_mask;
    assert_ne!(right_result, wrong_result);
    let circuit_unsatisfied: TestCircuit<BIT_PAIRS_16> = TestCircuit {
        a,
        b,
        result: wrong_result,
    };
    check_unsatisfied_circuit(&prover, &circuit_unsatisfied, &mut rng, &msg);
    // sanity check
    let circuit_satisfied: TestCircuit<BIT_PAIRS_16> = TestCircuit {
        a,
        b,
        result: right_result,
    };
    check_satisfied_circuit(
        &prover,
        &verifier,
        &pi,
        &circuit_satisfied,
        &mut rng,
        &"Sanity check should pass",
    );

    // Test with bits = 256
    //
    // Create new prover and verifier circuit descriptions
    const BIT_PAIRS_128: usize = 128;
    let (prover, verifier) =
        Compiler::compile::<TestCircuit<BIT_PAIRS_128>>(&pp, label)
            .expect("Circuit should compile");

    // Test sanity:
    let a = -BlsScalar::one();
    let b = BlsScalar::zero();
    let result = -BlsScalar::one();
    let circuit: TestCircuit<BIT_PAIRS_128> = TestCircuit { a, b, result };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test random works:
    let msg = "Circuit verification with random values should pass";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let circuit: TestCircuit<BIT_PAIRS_128> = TestCircuit::new(a, b);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test invalid circuit fails
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let right_result = a ^ b;
    let c = BlsScalar::random(&mut rng);
    let wrong_result = a ^ c;
    assert_ne!(right_result, wrong_result);
    let circuit: TestCircuit<BIT_PAIRS_128> = TestCircuit {
        a,
        b,
        result: wrong_result,
    };
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);
    // sanity check
    let circuit_satisfied: TestCircuit<BIT_PAIRS_128> = TestCircuit {
        a,
        b,
        result: right_result,
    };
    check_satisfied_circuit(
        &prover,
        &verifier,
        &pi,
        &circuit_satisfied,
        &mut rng,
        &"Sanity check should pass",
    );
}
