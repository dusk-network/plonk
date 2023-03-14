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
fn component_add_point() {
    pub struct TestCircuit {
        p1: JubJubExtended,
        p2: JubJubExtended,
        sum: JubJubExtended,
    }

    impl TestCircuit {
        pub fn new(
            p1: JubJubExtended,
            p2: JubJubExtended,
            sum: JubJubExtended,
        ) -> Self {
            Self { p1, p2, sum }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            let p1 = JubJubExtended::identity();
            let p2 = JubJubExtended::identity();
            let sum = JubJubExtended::identity();
            Self::new(p1.into(), p2.into(), sum.into())
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_p1 = composer.append_point(self.p1);
            let w_p2 = composer.append_point(self.p2);
            let w_sum = composer.append_point(self.sum);

            let sum_circuit = composer.component_add_point(w_p1, w_p2);

            composer.assert_equal_point(w_sum, sum_circuit);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_add_point";
    let rng = &mut StdRng::seed_from_u64(0xcafe);
    let capacity = 1 << 4;
    let (prover, verifier) =
        setup(capacity, rng, label, &TestCircuit::default());

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test identity works:
    let msg = "Random point addition should satisfy the circuit";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng);
    let p2 = JubJubExtended::identity();
    let sum = p1.clone();
    let circuit = TestCircuit::new(p1, p2, sum);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test distributivity:
    // a * GENERATOR + b * GENERATOR = (a + b) * GENERATOR
    let msg = "Random point addition should satisfy the circuit";
    let a = JubJubScalar::random(rng);
    let b = JubJubScalar::random(rng);
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * &a;
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * &b;
    let sum = dusk_jubjub::GENERATOR_EXTENDED * &(a + b);
    let circuit = TestCircuit::new(p1, p2, sum);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test random works:
    let msg = "Random point addition should satisfy the circuit";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng);
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng);
    let sum = p1 + p2;
    let circuit = TestCircuit::new(p1, p2, sum);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Unsatisfied circuit
    let msg = "Unsatisfied circuit should not pass";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(0xdecafu64);
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(0xcafeu64);
    let sum = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(0xcabu64);
    let circuit = TestCircuit::new(p1, p2, sum);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}

#[test]
fn component_mul_generator() {
    pub struct TestCircuit {
        scalar: JubJubScalar,
        generator: JubJubExtended,
        result: JubJubExtended,
    }

    impl TestCircuit {
        pub fn new(
            scalar: JubJubScalar,
            generator: JubJubExtended,
            result: JubJubExtended,
        ) -> Self {
            Self {
                scalar,
                generator,
                result,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::new(
                JubJubScalar::zero(),
                dusk_jubjub::GENERATOR_EXTENDED,
                JubJubExtended::identity(),
            )
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C: Composer>(&self, composer: &mut C) -> Result<(), Error> {
            let w_scalar = composer.append_witness(self.scalar);
            let w_result = composer.append_point(self.result);

            let circuit_result =
                composer.component_mul_generator(w_scalar, self.generator)?;

            composer.assert_equal_point(w_result, circuit_result);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_mul_generator";
    let rng = &mut StdRng::seed_from_u64(0xbead);
    let capacity = 1 << 9;
    let (prover, verifier) =
        setup(capacity, rng, label, &TestCircuit::default());

    // generator point and pi are the same for all tests
    let generator = dusk_jubjub::GENERATOR_EXTENDED;
    let pi = vec![];

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, msg);

    // Test:
    // GENERATOR * 1 = GENERATOR
    let msg = "Circuit with generator multiplied by one should pass";
    let scalar = JubJubScalar::one();
    let result = dusk_jubjub::GENERATOR_EXTENDED;
    let circuit = TestCircuit::new(scalar, generator, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, msg);

    // Test sanity:
    // GENERATOR * random
    let msg = "Circuit with random scalar should pass";
    let scalar = JubJubScalar::random(rng);
    let result = generator * &scalar;
    let circuit = TestCircuit::new(scalar, generator, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, msg);

    // Test unsatisfied:
    // GENERATOR * 7 != GENERATOR * 8
    let msg = "Unsatisfied circuit should not pass";
    let scalar = JubJubScalar::from(7u64);
    let result = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(8u64);
    let circuit = TestCircuit::new(scalar, generator, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);

    // Test unsatisfied:
    // invalid jubjub scalar panics
    let msg = "Unsatisfied circuit with invalid scalar should panic";
    let scalar = JubJubScalar::from_raw((-BlsScalar::one()).0);
    let result = dusk_jubjub::GENERATOR_EXTENDED;
    let circuit = TestCircuit::new(scalar, generator, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}

#[test]
fn component_mul_point() {
    pub struct TestCircuit {
        scalar: JubJubScalar,
        point: JubJubExtended,
        result: JubJubExtended,
    }

    impl TestCircuit {
        pub fn new(
            scalar: JubJubScalar,
            point: JubJubExtended,
            result: JubJubExtended,
        ) -> Self {
            Self {
                scalar,
                point,
                result,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            let scalar = JubJubScalar::from(0u64);
            let point = dusk_jubjub::GENERATOR_EXTENDED;
            let result = JubJubAffine::from_raw_unchecked(
                BlsScalar::zero(),
                BlsScalar::one(),
            )
            .into();

            Self::new(scalar, point, result)
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_scalar = composer.append_witness(self.scalar);
            let w_point = composer.append_point(self.point);
            let w_result = composer.append_point(self.result);

            let result_circuit =
                composer.component_mul_point(w_scalar, w_point);

            composer.assert_equal_point(w_result, result_circuit);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_mul_point";
    let rng = &mut StdRng::seed_from_u64(0xdeed);
    let capacity = 1 << 11;
    let (prover, verifier) =
        setup(capacity, rng, label, &TestCircuit::default());

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // GENERATOR * 1 = GENERATOR
    let msg = "Circuit with generator multiplied by one should pass";
    let scalar = JubJubScalar::one();
    let point = dusk_jubjub::GENERATOR_EXTENDED;
    let result = dusk_jubjub::GENERATOR_EXTENDED;
    let circuit = TestCircuit::new(scalar, point, result);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // random * 0 = (0, 1)
    let msg =
        "Circuit with random point multiplied by zero should be the o = (0,1)";
    let scalar = JubJubScalar::zero();
    let point = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng);
    let result: JubJubExtended =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::one())
            .into();
    let circuit = TestCircuit::new(scalar, point, result);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test: random works
    let msg = "Circuit with random point multiplication should pass";
    let scalar = JubJubScalar::random(rng);
    let point = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng);
    let result = point * &scalar;
    let circuit = TestCircuit::new(scalar, point, result);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Unsatisfied circuit
    let msg = "Unsatisfied circuit should not pass";
    let scalar = JubJubScalar::random(rng);
    let point = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng);
    let result = dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::random(rng);
    let circuit = TestCircuit::new(scalar, point, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, msg);
}
