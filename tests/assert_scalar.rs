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
    check_unsatisfied_circuit,
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
    let pp = PublicParameters::setup(capacity, rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

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
fn assert_equal_constant() {
    #[derive(Default)]
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

    // Test: public = None, constant = zero
    //
    // Compile common circuit descriptions for the prover and verifier
    let label = b"assert_equal_constant";
    let rng = &mut StdRng::seed_from_u64(0xfa11);
    let capacity = 1 << 4;
    let pp = PublicParameters::setup(capacity, rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

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

    // Test: public = Some(_), constant = zero
    //
    // Compile new circuit descriptions for the prover and verifier
    let scalar = BlsScalar::zero();
    let constant = BlsScalar::zero();
    let public = Some(BlsScalar::zero());
    let circuit = TestCircuit::new(scalar, constant, public);
    let (prover, verifier) =
        Compiler::compile_with_circuit(&pp, label, &circuit)
            .expect("Circuit should compile");

    // Test default works:
    // 0 = 0 + 0
    let msg = "Default circuit verification should pass";
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

    // Test: public = None, constant = random
    //
    // Compile new circuit descriptions for the prover and verifier
    let constant = BlsScalar::random(rng);
    let scalar = constant.clone();
    let public = None;
    let circuit = TestCircuit::new(scalar, constant, public);
    let (prover, verifier) =
        Compiler::compile_with_circuit(&pp, label, &circuit)
            .expect("Circuit should compile");

    // Test default works:
    // x = x + None
    let msg = "Default circuit verification should pass";
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test public input doesn't match
    let msg = "Satisfied circuit should not verify because pi length is not the same as in circuit description";
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

    // Test: public = Some(_), constant = random
    //
    // Compile new circuit descriptions for the prover and verifier
    let constant = BlsScalar::random(rng);
    let scalar = constant.clone();
    let public = Some(BlsScalar::zero());
    let circuit = TestCircuit::new(scalar, constant, public);
    let (prover, verifier) =
        Compiler::compile_with_circuit(&pp, label, &circuit)
            .expect("Circuit should compile");

    // Test default works:
    // 0 = 0 + 0
    let msg = "Default circuit verification should pass";
    let pi = vec![BlsScalar::zero()];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test:
    // witness = constant + pi
    let msg = "Satisfied circuit should verify";
    let scalar = BlsScalar::random(rng);
    let public_value = scalar - constant;
    let public = Some(public_value);
    let pi = vec![public_value];
    let circuit = TestCircuit::new(scalar, constant, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test public input doesn't match
    let msg = "Satisfied circuit should not verify because pi length is not the same as in circuit description";
    let scalar = constant.clone();
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
