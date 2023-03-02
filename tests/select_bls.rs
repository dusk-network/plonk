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
fn component_select() {
    pub struct TestCircuit {
        bit: BlsScalar,
        value_a: BlsScalar,
        value_b: BlsScalar,
        result: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(
            bit: BlsScalar,
            value_a: BlsScalar,
            value_b: BlsScalar,
            result: BlsScalar,
        ) -> Self {
            Self {
                bit,
                value_a,
                value_b,
                result,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::new(
                BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::one(),
            )
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_bit = composer.append_witness(self.bit);
            let w_value_a = composer.append_witness(self.value_a);
            let w_value_b = composer.append_witness(self.value_b);
            let w_result = composer.append_witness(self.result);

            let result_circuit =
                composer.component_select(w_bit, w_value_a, w_value_b);

            composer.assert_equal(w_result, result_circuit);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_select";
    let rng = &mut StdRng::seed_from_u64(0xbeef);
    let capacity = 1 << 5;
    let (prover, verifier) =
        setup(capacity, rng, label, &TestCircuit::default());

    // public inputs to be used by all tests
    let pi = vec![];

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works
    let msg = "Circuit with bit = 1 that selects value_a should pass";
    let bit = BlsScalar::one();
    let value_a = BlsScalar::one();
    let value_b = BlsScalar::zero();
    let result = value_a.clone();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works with random
    let msg = "Circuit with bit = 1 that selects value_a should pass";
    let bit = BlsScalar::one();
    let value_a = BlsScalar::random(rng);
    let value_b = BlsScalar::random(rng);
    let result = value_a.clone();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works
    let msg = "Circuit with bit = 0 that selects value_b should pass";
    let bit = BlsScalar::zero();
    let value_a = BlsScalar::one();
    let value_b = BlsScalar::zero();
    let result = value_b.clone();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works with random
    let msg = "Circuit with bit = 0 that selects value_b should pass";
    let bit = BlsScalar::zero();
    let value_a = BlsScalar::random(rng);
    let value_b = BlsScalar::random(rng);
    let result = value_b.clone();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test invalid bit passes (bit should be constrained outside of the
    // `select` component)
    let msg = "Circuit with invalid bit shouldn't pass";
    let bit = BlsScalar::random(rng);
    let value_a = BlsScalar::zero();
    let value_b = BlsScalar::zero();
    let result = BlsScalar::zero();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one fails
    let msg = "Circuit with bit = 1 that selects value_b shouldn't pass";
    let bit = BlsScalar::one();
    let value_a = BlsScalar::one();
    let value_b = BlsScalar::zero();
    let result = value_b.clone();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test one fails with random
    let msg = "Circuit with bit = 1 that selects value_b shouldn't pass";
    let bit = BlsScalar::one();
    let value_a = BlsScalar::random(rng);
    let value_b = BlsScalar::random(rng);
    let result = value_b.clone();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails
    let msg = "Circuit with bit = 0 that selects value_a shouldn't pass";
    let bit = BlsScalar::zero();
    let value_a = BlsScalar::one();
    let value_b = BlsScalar::zero();
    let result = value_a.clone();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails with random
    let msg = "Circuit with bit = 0 that selects value_a shouldn't pass";
    let bit = BlsScalar::zero();
    let value_a = BlsScalar::random(rng);
    let value_b = BlsScalar::random(rng);
    let result = value_a.clone();
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::one();
    let value_a = BlsScalar::random(rng);
    let value_b = BlsScalar::random(rng);
    let result = BlsScalar::random(rng);
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::zero();
    let value_a = BlsScalar::random(rng);
    let value_b = BlsScalar::random(rng);
    let result = BlsScalar::random(rng);
    let circuit = TestCircuit::new(bit, value_a, value_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}

#[test]
fn component_select_one() {
    pub struct TestCircuit {
        bit: BlsScalar,
        value: BlsScalar,
        result: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(
            bit: BlsScalar,
            value: BlsScalar,
            result: BlsScalar,
        ) -> Self {
            Self { bit, value, result }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::new(BlsScalar::one(), BlsScalar::one(), BlsScalar::one())
        }
    }
    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_bit = composer.append_witness(self.bit);
            let w_value = composer.append_witness(self.value);
            let w_result = composer.append_witness(self.result);

            let result_circuit = composer.component_select_one(w_bit, w_value);

            composer.assert_equal(w_result, result_circuit);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_select_one";
    let rng = &mut StdRng::seed_from_u64(0xfee);
    let capacity = 1 << 5;
    let (prover, verifier) =
        setup(capacity, rng, label, &TestCircuit::default());

    // public inputs to be used by all tests
    let pi = vec![];

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works
    let msg = "Circuit with bit = 1 that selects value should pass";
    let bit = BlsScalar::one();
    let value = BlsScalar::one();
    let result = value.clone();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works with random
    let msg = "Circuit with bit = 1 that selects value should pass";
    let bit = BlsScalar::one();
    let value = BlsScalar::random(rng);
    let result = value.clone();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works
    let msg = "Circuit with bit = 0 that selects 1 should pass";
    let bit = BlsScalar::zero();
    let value = BlsScalar::zero();
    let result = BlsScalar::one();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works with random
    let msg = "Circuit with bit = 0 that selects 1 should pass";
    let bit = BlsScalar::zero();
    let value = BlsScalar::random(rng);
    let result = BlsScalar::one();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test invalid bit passes (bit should be constrained outside of the
    // `select` component)
    let msg = "Circuit with invalid bit can pass";
    let bit = BlsScalar::random(rng);
    let value = BlsScalar::one();
    let result = BlsScalar::one();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one fails
    let msg = "Circuit with bit = 1 that selects 1 shouldn't pass";
    let bit = BlsScalar::one();
    let value = BlsScalar::zero();
    let result = BlsScalar::one();
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test one fails with random
    let msg = "Circuit with bit = 1 that selects 1 shouldn't pass";
    let bit = BlsScalar::one();
    let value = BlsScalar::random(rng);
    let result = BlsScalar::one();
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails
    let msg = "Circuit with bit = 0 that selects value shouldn't pass";
    let bit = BlsScalar::zero();
    let value = BlsScalar::zero();
    let result = BlsScalar::zero();
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails with random
    let msg = "Circuit with bit = 0 that selects value shouldn't pass";
    let bit = BlsScalar::zero();
    let value = BlsScalar::random(rng);
    let result = value.clone();
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::one();
    let value = BlsScalar::random(rng);
    let result = BlsScalar::random(rng);
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::zero();
    let value = BlsScalar::random(rng);
    let result = BlsScalar::random(rng);
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}

#[test]
fn component_select_zero() {
    pub struct TestCircuit {
        bit: BlsScalar,
        value: BlsScalar,
        result: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(
            bit: BlsScalar,
            value: BlsScalar,
            result: BlsScalar,
        ) -> Self {
            Self { bit, value, result }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::new(BlsScalar::zero(), BlsScalar::zero(), BlsScalar::zero())
        }
    }
    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_bit = composer.append_witness(self.bit);
            let w_value = composer.append_witness(self.value);
            let w_result = composer.append_witness(self.result);

            let result_circuit = composer.component_select_zero(w_bit, w_value);

            composer.assert_equal(w_result, result_circuit);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_select_zero";
    let rng = &mut StdRng::seed_from_u64(0xca11);
    let capacity = 1 << 5;
    let (prover, verifier) =
        setup(capacity, rng, label, &TestCircuit::default());

    // public inputs to be used by all tests
    let pi = vec![];

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works
    let msg = "Circuit with bit = 1 that selects value should pass";
    let bit = BlsScalar::one();
    let value = BlsScalar::one();
    let result = value.clone();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works with random
    let msg = "Circuit with bit = 1 that selects value should pass";
    let bit = BlsScalar::one();
    let value = BlsScalar::random(rng);
    let result = value.clone();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works
    let msg = "Circuit with bit = 0 that selects 0 should pass";
    let bit = BlsScalar::zero();
    let value = BlsScalar::one();
    let result = BlsScalar::zero();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works with random
    let msg = "Circuit with bit = 0 that selects 0 should pass";
    let bit = BlsScalar::zero();
    let value = BlsScalar::random(rng);
    let result = BlsScalar::zero();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test invalid bit passes (bit should be constrained outside of the
    // `select` component)
    let msg = "Circuit with invalid bit can pass";
    let bit = BlsScalar::random(rng);
    let value = BlsScalar::zero();
    let result = BlsScalar::zero();
    let circuit = TestCircuit::new(bit, value, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one fails
    let msg = "Circuit with bit = 1 that selects 1 shouldn't pass";
    let bit = BlsScalar::one();
    let value = BlsScalar::zero();
    let result = BlsScalar::one();
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test one fails with random
    let msg = "Circuit with bit = 1 that selects 0 shouldn't pass";
    let bit = BlsScalar::one();
    let value = BlsScalar::random(rng);
    let result = BlsScalar::zero();
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails
    let msg = "Circuit with bit = 0 that selects value shouldn't pass";
    let bit = BlsScalar::zero();
    let value = BlsScalar::one();
    let result = BlsScalar::one();
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails with random
    let msg = "Circuit with bit = 0 that selects value shouldn't pass";
    let bit = BlsScalar::zero();
    let value = BlsScalar::random(rng);
    let result = value.clone();
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::one();
    let value = BlsScalar::random(rng);
    let result = BlsScalar::random(rng);
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::zero();
    let value = BlsScalar::random(rng);
    let result = BlsScalar::random(rng);
    let circuit = TestCircuit::new(bit, value, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}
