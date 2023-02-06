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
fn component_select_point() {
    pub struct TestCircuit {
        bit: BlsScalar,
        point_a: JubJubAffine,
        point_b: JubJubAffine,
        result: JubJubAffine,
    }

    impl TestCircuit {
        pub fn new(
            bit: BlsScalar,
            point_a: JubJubAffine,
            point_b: JubJubAffine,
            result: JubJubAffine,
        ) -> Self {
            Self {
                bit,
                point_a,
                point_b,
                result,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::new(
                BlsScalar::zero(),
                JubJubAffine::identity(),
                JubJubAffine::identity(),
                JubJubAffine::identity(),
            )
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_bit = composer.append_witness(self.bit);
            let w_point_a = composer.append_point(self.point_a);
            let w_point_b = composer.append_point(self.point_b);
            let w_result = composer.append_point(self.result);

            let result_circuit =
                composer.component_select_point(w_bit, w_point_a, w_point_b);

            composer.assert_equal_point(w_result, result_circuit);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_select_point";
    let rng = &mut StdRng::seed_from_u64(0xce11);
    let capacity = 1 << 5;
    let (prover, verifier) = setup(capacity, rng, label);

    // public inputs to be used by all tests
    let pi = vec![];

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works
    let msg = "Circuit with bit = 1 that selects point_a should pass";
    let bit = BlsScalar::one();
    let point_a = dusk_jubjub::GENERATOR;
    let point_b = JubJubAffine::identity();
    let result = point_a.clone();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works with random
    let msg = "Circuit with bit = 1 that selects point_a should pass";
    let bit = BlsScalar::one();
    let point_a: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let point_b: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result = point_a.clone();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works
    let msg = "Circuit with bit = 0 that selects point_b should pass";
    let bit = BlsScalar::zero();
    let point_a = dusk_jubjub::GENERATOR;
    let point_b = JubJubAffine::identity();
    let result = point_b.clone();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works with random
    let msg = "Circuit with bit = 0 that selects point_b should pass";
    let bit = BlsScalar::zero();
    let point_a: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let point_b: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result = point_b.clone();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test invalid bit passes (bit should be constrained outside of the
    // `select` component)
    let msg = "Circuit with invalid bit shouldn't pass";
    let bit = BlsScalar::random(rng);
    let point_a = JubJubAffine::identity();
    let point_b = JubJubAffine::identity();
    let result = JubJubAffine::identity();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one fails
    let msg = "Circuit with bit = 1 that selects point_b shouldn't pass";
    let bit = BlsScalar::one();
    let point_a = dusk_jubjub::GENERATOR;
    let point_b = JubJubAffine::identity();
    let result = point_b.clone();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test one fails with random
    let msg = "Circuit with bit = 1 that selects point_b shouldn't pass";
    let bit = BlsScalar::one();
    let point_a: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let point_b: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result = point_b.clone();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails
    let msg = "Circuit with bit = 0 that selects point_a shouldn't pass";
    let bit = BlsScalar::zero();
    let point_a = dusk_jubjub::GENERATOR;
    let point_b = JubJubAffine::identity();
    let result = point_a.clone();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails with random
    let msg = "Circuit with bit = 0 that selects point_a shouldn't pass";
    let bit = BlsScalar::zero();
    let point_a: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let point_b: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result = point_a.clone();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::one();
    let point_a: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let point_b: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::zero();
    let point_a: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let point_b: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let circuit = TestCircuit::new(bit, point_a, point_b, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}

#[test]
fn component_select_identity() {
    pub struct TestCircuit {
        bit: BlsScalar,
        point: JubJubAffine,
        result: JubJubAffine,
    }

    impl TestCircuit {
        pub fn new(
            bit: BlsScalar,
            point: JubJubAffine,
            result: JubJubAffine,
        ) -> Self {
            Self { bit, point, result }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::new(
                BlsScalar::zero(),
                JubJubAffine::identity(),
                JubJubAffine::identity(),
            )
        }
    }
    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_bit = composer.append_witness(self.bit);
            let w_point = composer.append_point(self.point);
            let w_result = composer.append_point(self.result);

            let result_circuit =
                composer.component_select_identity(w_bit, w_point);

            composer.assert_equal_point(w_result, result_circuit);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_select_one";
    let rng = &mut StdRng::seed_from_u64(0xfee);
    let capacity = 1 << 5;
    let (prover, verifier) = setup(capacity, rng, label);

    // public inputs to be used by all tests
    let pi = vec![];

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works
    let msg = "Circuit with bit = 1 that selects point should pass";
    let bit = BlsScalar::one();
    let point = dusk_jubjub::GENERATOR;
    let result = point.clone();
    let circuit = TestCircuit::new(bit, point, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one works with random
    let msg = "Circuit with bit = 1 that selects point should pass";
    let bit = BlsScalar::one();
    let point: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result = point.clone();
    let circuit = TestCircuit::new(bit, point, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works
    let msg = "Circuit with bit = 0 that selects identity should pass";
    let bit = BlsScalar::zero();
    let point = dusk_jubjub::GENERATOR;
    let result = JubJubAffine::identity();
    let circuit = TestCircuit::new(bit, point, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test zero works with random
    let msg = "Circuit with bit = 0 that selects identity should pass";
    let bit = BlsScalar::zero();
    let point: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result = JubJubAffine::identity();
    let circuit = TestCircuit::new(bit, point, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test invalid bit passes (bit should be constrained outside of the
    // `select` component)
    let msg = "Circuit with invalid bit can pass";
    let bit = BlsScalar::random(rng);
    let point = JubJubAffine::identity();
    let result = JubJubAffine::identity();
    let circuit = TestCircuit::new(bit, point, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test one fails
    let msg = "Circuit with bit = 1 that selects identity shouldn't pass";
    let bit = BlsScalar::one();
    let point = dusk_jubjub::GENERATOR;
    let result = JubJubAffine::identity();
    let circuit = TestCircuit::new(bit, point, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test one fails with random
    let msg = "Circuit with bit = 1 that selects identity shouldn't pass";
    let bit = BlsScalar::one();
    let point: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result = JubJubAffine::identity();
    let circuit = TestCircuit::new(bit, point, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails
    let msg = "Circuit with bit = 0 that selects point shouldn't pass";
    let bit = BlsScalar::zero();
    let point = dusk_jubjub::GENERATOR;
    let result = point.clone();
    let circuit = TestCircuit::new(bit, point, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test zero fails with random
    let msg = "Circuit with bit = 0 that selects point shouldn't pass";
    let bit = BlsScalar::zero();
    let point: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result = point.clone();
    let circuit = TestCircuit::new(bit, point, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::one();
    let point: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let circuit = TestCircuit::new(bit, point, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test random fails
    let msg =
        "Circuit with random result shouldn't pass no matter the selector bit";
    let bit = BlsScalar::zero();
    let point: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let result: JubJubAffine =
        (dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng)).into();
    let circuit = TestCircuit::new(bit, point, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}
