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
fn gate_add_mul() {
    #[derive(Default)]
    pub struct TestCircuit {
        a: BlsScalar,
        b: BlsScalar,
        d: BlsScalar,
        public: BlsScalar,
        result: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(
            a: BlsScalar,
            b: BlsScalar,
            d: BlsScalar,
            public: BlsScalar,
            result: BlsScalar,
        ) -> Self {
            Self {
                a,
                b,
                d,
                public,
                result,
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_witness(self.b);
            let w_d = composer.append_witness(self.d);

            let result_expected = composer.append_witness(self.result);

            let constraint = Constraint::new()
                .left(1)
                .right(1)
                .mult(1)
                .fourth(1)
                .a(w_a)
                .b(w_b)
                .d(w_d)
                .public(self.public)
                .constant(BlsScalar::one());

            let result_add = composer.gate_add(constraint);
            let result_mul = composer.gate_mul(constraint);

            // At the time of writing both the addition and multiplication gates
            // are the same internally
            composer.assert_equal(result_expected, result_add);
            composer.assert_equal(result_expected, result_mul);

            Ok(())
        }
    }

    let label = b"gate_add_mul";
    let mut rng = StdRng::seed_from_u64(0xbe11);
    let capacity = 1 << 4;

    // Test: public = zero, constant = zero, selectors = one
    //
    // Compile common circuit descriptions for the prover and verifier
    let public = BlsScalar::zero();
    const CONST: BlsScalar = BlsScalar::one();
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let result = a + b + a * b + d + public + CONST;
    let pi = vec![public, public];
    let circuit = TestCircuit::new(a, b, d, public, result);
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

    // Test default works:
    let msg = "Default circuit verification should pass";
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test satisfied circuit:
    // a + b + a·b + d + public + 1 = result
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::one();
    let result = a + b + a * b + d + public + CONST;
    let circuit = TestCircuit::new(a, b, d, public, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test satisfied circuit:
    // a + b + a·b + d + public + 1 = result
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let d = BlsScalar::random(&mut rng);
    let public = BlsScalar::random(&mut rng);
    let pi = vec![public, public];
    let result = a + b + a * b + d + public + CONST;
    let circuit = TestCircuit::new(a, b, d, public, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test unsatisfied circuit:
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let d = BlsScalar::random(&mut rng);
    let public = BlsScalar::random(&mut rng);
    let result = a + b + a * b + d + public + CONST + BlsScalar::one();
    let circuit = TestCircuit::new(a, b, d, public, result);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test unsatisfied circuit:
    // a + b + a·b + d + public + 1 = result
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::one();
    let public = BlsScalar::one();
    let result = BlsScalar::from(42);
    let circuit = TestCircuit::new(a, b, d, public, result);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test circuit where circuit description doesn't match
    let msg = "Proof creation of circuit that has different constant than in description should fail";
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let public = BlsScalar::from(2u64);
    let incorrect_constant = -BlsScalar::from(2u64);
    let result = a + b + a * b + d + public + incorrect_constant;
    let circuit = TestCircuit::new(a, b, d, public, result);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);
}
