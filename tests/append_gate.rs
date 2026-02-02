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
fn append_gate() {
    #[derive(Default)]
    pub struct TestCircuit {
        a: BlsScalar,
        b: BlsScalar,
        c: BlsScalar,
        d: BlsScalar,
        public: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(
            a: BlsScalar,
            b: BlsScalar,
            c: BlsScalar,
            d: BlsScalar,
            public: BlsScalar,
        ) -> Self {
            Self { a, b, c, d, public }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let a = composer.append_witness(self.a);
            let b = composer.append_witness(self.b);
            let c = composer.append_witness(self.c);
            let d = composer.append_witness(self.d);

            let constraint = Constraint::new()
                .left(1)
                .right(1)
                .mult(1)
                .fourth(1)
                .output(1)
                .a(a)
                .b(b)
                .c(c)
                .d(d)
                .public(self.public)
                .constant(BlsScalar::zero());

            composer.append_gate(constraint);

            Ok(())
        }
    }

    let label = b"append_gate_with_constant";
    let mut rng = StdRng::seed_from_u64(0x1ab);
    let capacity = 1 << 4;

    // Test: constant = zero, selectors = one
    //
    // Compile common circuit descriptions for the prover and verifier
    let public = BlsScalar::zero();
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let c = BlsScalar::zero();
    let d = BlsScalar::zero();
    let pi = vec![public];
    let circuit = TestCircuit::new(a, b, c, d, public);
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

    // Test default works:
    let msg = "Default circuit verification should pass";
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·c + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let c = -BlsScalar::from(4);
    let d = BlsScalar::one();
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·c + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::zero();
    let c = -BlsScalar::one();
    let d = BlsScalar::zero();
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·c + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::zero();
    let b = BlsScalar::one();
    let c = -BlsScalar::one();
    let d = BlsScalar::zero();
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·c + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let c = -BlsScalar::from(3u64);
    let d = BlsScalar::zero();
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·c + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = -BlsScalar::one();
    let b = BlsScalar::zero();
    let c = BlsScalar::zero();
    let d = BlsScalar::one();
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·c + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let d = BlsScalar::random(&mut rng);
    let public = BlsScalar::from(42);
    let c = -(a + b + a * b + d + public);
    let pi = vec![public];
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test unsatisfied circuit:
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::random(&mut rng);
    let b = BlsScalar::random(&mut rng);
    let c = BlsScalar::random(&mut rng);
    let d = BlsScalar::random(&mut rng);
    let public = BlsScalar::random(&mut rng);
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test unsatisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·c + q_4·d + public + constant = 0
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let c = BlsScalar::one();
    let d = BlsScalar::one();
    let public = BlsScalar::one();
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test unsatisfied circuit
    let msg = "Verification of unsatisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let c = BlsScalar::one();
    let d = BlsScalar::one();
    let public = BlsScalar::one();
    let circuit = TestCircuit::new(a, b, c, d, public);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);
}
