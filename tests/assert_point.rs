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
fn assert_equal_point() {
    pub struct TestCircuit {
        p1: JubJubAffine,
        p2: JubJubAffine,
    }

    impl TestCircuit {
        pub fn new(p1: JubJubAffine, p2: JubJubAffine) -> Self {
            Self { p1, p2 }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                p1: dusk_jubjub::GENERATOR,
                p2: dusk_jubjub::GENERATOR,
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_p1 = composer.append_point(self.p1);
            let w_p2 = composer.append_point(self.p2);
            composer.assert_equal_point(w_p1, w_p2);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"assert_equal_point";
    let rng = &mut StdRng::seed_from_u64(0xdecaf);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // Test default works:
    // GENERATOR = GENERATOR
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test sanity:
    // 42 * GENERATOR = 42 * GENERATOR
    let msg = "Circuit verification with equal points should pass";
    let scalar = JubJubScalar::from(42u64);
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * &scalar;
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * &scalar;
    let circuit = TestCircuit::new(p1.into(), p2.into());
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // GENERATOR != 42 * GENERATOR
    let msg = "prover should fail because the points are not equal";
    let scalar = JubJubScalar::from(42u64);
    let p1 = dusk_jubjub::GENERATOR;
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * &scalar;
    let circuit = TestCircuit::new(p1, p2.into());
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test:
    // assertion of points with different x-coordinates fails
    let msg = "prover should fail because the x-coordinates of the points are not equal";
    let p1 =
        JubJubAffine::from_raw_unchecked(BlsScalar::one(), BlsScalar::one());
    let p2 =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::one());
    let circuit = TestCircuit::new(p1, p2);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test:
    // assertion of points with different y-coordinates fails
    let msg = "prover should fail because the y-coordinates of the points are not equal";
    let p1 =
        JubJubAffine::from_raw_unchecked(BlsScalar::one(), BlsScalar::one());
    let p2 =
        JubJubAffine::from_raw_unchecked(BlsScalar::one(), BlsScalar::zero());
    let circuit = TestCircuit::new(p1, p2);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}

#[test]
fn assert_equal_public_point() {
    pub struct TestCircuit {
        point: JubJubAffine,
        public: JubJubAffine,
    }

    impl TestCircuit {
        pub fn new(point: JubJubAffine, public: JubJubAffine) -> Self {
            Self { point, public }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                point: dusk_jubjub::GENERATOR,
                public: dusk_jubjub::GENERATOR,
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_point = composer.append_point(self.point);
            composer.assert_equal_public_point(w_point, self.public);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"assert_equal_public_point";
    let rng = &mut StdRng::seed_from_u64(0xfeed);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // Test default works:
    // GENERATOR = GENERATOR
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![
        dusk_jubjub::GENERATOR.get_x(),
        dusk_jubjub::GENERATOR.get_y(),
    ];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test sanity:
    // 42 * GENERATOR = 42 * GENERATOR
    let msg = "Circuit verification with equal points should pass";
    let scalar = JubJubScalar::from(42u64);
    let point = dusk_jubjub::GENERATOR_EXTENDED * &scalar;
    let public = dusk_jubjub::GENERATOR_EXTENDED * &scalar;
    let circuit = TestCircuit::new(point.into(), public.into());
    let public_affine: JubJubAffine = public.into();
    let pi = vec![public_affine.get_x(), public_affine.get_y()];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // GENERATOR != 42 * GENERATOR
    let msg = "prover should fail because the points are not equal";
    let scalar = JubJubScalar::from(42u64);
    let point = dusk_jubjub::GENERATOR;
    let public = dusk_jubjub::GENERATOR_EXTENDED * &scalar;
    let circuit = TestCircuit::new(point, public.into());
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test:
    // assertion of points with different x-coordinates fails
    let msg = "prover should fail because the x-coordinates of the points are not equal";
    let point =
        JubJubAffine::from_raw_unchecked(BlsScalar::one(), BlsScalar::one());
    let public =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::one());
    let circuit = TestCircuit::new(point, public);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test:
    // assertion of points with different y-coordinates fails
    let msg = "prover should fail because the y-coordinates of the points are not equal";
    let point =
        JubJubAffine::from_raw_unchecked(BlsScalar::one(), BlsScalar::one());
    let public =
        JubJubAffine::from_raw_unchecked(BlsScalar::one(), BlsScalar::zero());
    let circuit = TestCircuit::new(point, public);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}
