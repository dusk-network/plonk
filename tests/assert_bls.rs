// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

mod common;
use common::{
    check_satisfied_circuit, check_satisfied_circuit_fails,
    check_unsatisfied_circuit, setup,
};

#[test]
fn assert_equal() {
    pub struct TestCircuit {
        scalar_a: BlsScalar,
        scalar_b: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(scalar_a: BlsScalar, scalar_b: BlsScalar) -> Self {
            Self { scalar_a, scalar_b }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                scalar_a: BlsScalar::zero(),
                scalar_b: BlsScalar::zero(),
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_scalar_a = composer.append_witness(self.scalar_a);
            let w_scalar_b = composer.append_witness(self.scalar_b);

            composer.assert_equal(w_scalar_a, w_scalar_b);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"assert_equal_constant_without_pi";
    let rng = &mut StdRng::seed_from_u64(0xc1adde);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // public input to be used by all tests
    let pi = vec![];

    // Test default works:
    // 0 = 0
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // 1 = 1
    let msg = "Satisfied circuit verification should pass";
    let scalar_a = BlsScalar::one();
    let scalar_b = BlsScalar::one();
    let circuit = TestCircuit::new(scalar_a, scalar_b);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // x = x
    let msg = "Satisfied circuit verification should pass";
    let scalar_a = BlsScalar::random(rng);
    let scalar_b = scalar_a.clone();
    let circuit = TestCircuit::new(scalar_a, scalar_b);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // 1 != 0
    let msg = "Proof creation should fail with unsatisfied circuit";
    let scalar_a = BlsScalar::one();
    let scalar_b = BlsScalar::zero();
    let circuit = TestCircuit::new(scalar_a, scalar_b);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test:
    // x != y
    let msg = "Proof creation should fail with unsatisfied circuit";
    let scalar_a = BlsScalar::random(rng);
    let scalar_b = BlsScalar::random(rng);
    let circuit = TestCircuit::new(scalar_a, scalar_b);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}

#[test]
fn assert_equal_constant_without_pi() {
    pub struct TestCircuit {
        scalar: BlsScalar,
        constant: BlsScalar,
        public: Option<BlsScalar>,
    }

    impl TestCircuit {
        pub fn new(
            scalar: BlsScalar,
            constant: BlsScalar,
            public: Option<BlsScalar>,
        ) -> Self {
            Self {
                scalar,
                constant,
                public,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                scalar: BlsScalar::zero(),
                constant: BlsScalar::zero(),
                public: None,
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_scalar = composer.append_witness(self.scalar);

            composer.assert_equal_constant(
                w_scalar,
                self.constant,
                self.public,
            );

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"assert_equal_constant_without_pi";
    let rng = &mut StdRng::seed_from_u64(0xfa11);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // Test default works:
    // 0 = 0 + None
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test public input doesn't match
    let msg = "Satisfied circuit should not verify because pi length is not the same as in circuit description";
    let scalar = BlsScalar::zero();
    let constant = BlsScalar::zero();
    let public_value = BlsScalar::zero();
    let public = Some(public_value);
    let pi = vec![public_value];
    let circuit = TestCircuit::new(scalar, constant, public);
    check_satisfied_circuit_fails(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test constant doesn't match
    let msg = "Proof creation should not be possible with different constant than in circuit description";
    let scalar = BlsScalar::one();
    let constant = BlsScalar::one();
    let public = None;
    let circuit = TestCircuit::new(scalar, constant, public);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}

#[test]
fn assert_equal_constant_with_pi() {
    pub struct TestCircuit {
        scalar: BlsScalar,
        constant: BlsScalar,
        public: Option<BlsScalar>,
    }

    impl TestCircuit {
        pub fn new(
            scalar: BlsScalar,
            constant: BlsScalar,
            public: Option<BlsScalar>,
        ) -> Self {
            Self {
                scalar,
                constant,
                public,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                scalar: BlsScalar::zero(),
                constant: BlsScalar::zero(),
                public: Some(BlsScalar::zero()),
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_scalar = composer.append_witness(self.scalar);

            composer.assert_equal_constant(
                w_scalar,
                self.constant,
                self.public,
            );

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"assert_equal_constant_with_pi";
    let rng = &mut StdRng::seed_from_u64(0xfa11);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // Test default works:
    // 0 = 0 + 0
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![BlsScalar::zero()];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // witness = 0 + pi
    let msg = "Satisfied circuit should verify";
    let scalar = BlsScalar::random(rng);
    let constant = BlsScalar::zero();
    let public_value = scalar.clone();
    let public = Some(public_value);
    let pi = vec![public_value];
    let circuit = TestCircuit::new(scalar, constant, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test public input doesn't match
    let msg = "Satisfied circuit should not verify because pi length is not the same as in circuit description";
    let scalar = BlsScalar::zero();
    let constant = BlsScalar::zero();
    let public = None;
    let pi = vec![];
    let circuit = TestCircuit::new(scalar, constant, public);
    check_satisfied_circuit_fails(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test constant doesn't match
    let msg = "Proof creation should not be possible with different constant than in circuit description";
    let scalar = BlsScalar::one();
    let constant = BlsScalar::one();
    let public = Some(BlsScalar::zero());
    let circuit = TestCircuit::new(scalar, constant, public);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}

#[test]
fn assert_equal_random_constant_without_pi() {
    const CONSTANT: BlsScalar = BlsScalar::from_raw([0x42, 0x42, 0x42, 0x42]);

    pub struct TestCircuit {
        scalar: BlsScalar,
        constant: BlsScalar,
        public: Option<BlsScalar>,
    }

    impl TestCircuit {
        pub fn new(
            scalar: BlsScalar,
            constant: BlsScalar,
            public: Option<BlsScalar>,
        ) -> Self {
            Self {
                scalar,
                constant,
                public,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                scalar: CONSTANT,
                constant: CONSTANT,
                public: None,
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_scalar = composer.append_witness(self.scalar);

            composer.assert_equal_constant(
                w_scalar,
                self.constant,
                self.public,
            );

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"assert_equal_random_constant_without_pi";
    let rng = &mut StdRng::seed_from_u64(0xfa11);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // Test default works:
    // x = x + None
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test public input doesn't match
    let msg = "Satisfied circuit should not verify because pi length is not the same as in circuit description";
    let scalar = CONSTANT;
    let constant = CONSTANT;
    let public_value = BlsScalar::zero();
    let public = Some(public_value);
    let pi = vec![public_value];
    let circuit = TestCircuit::new(scalar, constant, public);
    check_satisfied_circuit_fails(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test constant doesn't match
    let msg = "Proof creation should not be possible with different constant than in circuit description";
    let scalar = BlsScalar::one();
    let constant = BlsScalar::one();
    let public = None;
    let circuit = TestCircuit::new(scalar, constant, public);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}

#[test]
fn assert_equal_random_constant_with_pi() {
    const CONSTANT: BlsScalar = BlsScalar::from_raw([0x42, 0x42, 0x42, 0x42]);

    pub struct TestCircuit {
        scalar: BlsScalar,
        constant: BlsScalar,
        public: Option<BlsScalar>,
    }

    impl TestCircuit {
        pub fn new(
            scalar: BlsScalar,
            constant: BlsScalar,
            public: Option<BlsScalar>,
        ) -> Self {
            Self {
                scalar,
                constant,
                public,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                scalar: CONSTANT,
                constant: CONSTANT,
                public: Some(BlsScalar::zero()),
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_scalar = composer.append_witness(self.scalar);

            composer.assert_equal_constant(
                w_scalar,
                self.constant,
                self.public,
            );

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"assert_equal_random_constant_with_pi";
    let rng = &mut StdRng::seed_from_u64(0xfa11);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // Test default works:
    // 0 = 0 + 0
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![BlsScalar::zero()];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // witness = constant + pi
    let msg = "Satisfied circuit should verify";
    let scalar = BlsScalar::random(rng);
    let constant = CONSTANT;
    let public_value = scalar - constant;
    let public = Some(public_value);
    let pi = vec![public_value];
    let circuit = TestCircuit::new(scalar, constant, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test public input doesn't match
    let msg = "Satisfied circuit should not verify because pi length is not the same as in circuit description";
    let scalar = CONSTANT;
    let constant = CONSTANT;
    let public = None;
    let pi = vec![];
    let circuit = TestCircuit::new(scalar, constant, public);
    check_satisfied_circuit_fails(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test constant doesn't match
    let msg = "Proof creation should not be possible with different constant than in circuit description";
    let scalar = BlsScalar::one();
    let constant = BlsScalar::one();
    let public = Some(BlsScalar::zero());
    let circuit = TestCircuit::new(scalar, constant, public);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}
