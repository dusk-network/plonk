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
fn gate_add_mul() {
    #[derive(Default)]
    pub struct TestCircuit {
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_m: BlsScalar,
        q_k: BlsScalar,
        a: BlsScalar,
        b: BlsScalar,
        d: BlsScalar,
        public: BlsScalar,
        constant: BlsScalar,
        result: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(
            q_l: BlsScalar,
            q_r: BlsScalar,
            q_m: BlsScalar,
            q_k: BlsScalar,
            a: BlsScalar,
            b: BlsScalar,
            d: BlsScalar,
            public: BlsScalar,
            constant: BlsScalar,
            result: BlsScalar,
        ) -> Self {
            Self {
                q_l,
                q_r,
                q_m,
                q_k,
                a,
                b,
                d,
                public,
                constant,
                result,
            }
        }
    }

    impl Circuit for TestCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_witness(self.b);
            let w_d = composer.append_witness(self.d);

            let result_expected = composer.append_witness(self.result);

            let constraint = Constraint::new()
                .left(self.q_l)
                .right(self.q_r)
                .mult(self.q_m)
                .fourth(self.q_k)
                .a(w_a)
                .b(w_b)
                .d(w_d)
                .public(self.public)
                .constant(self.constant);

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
    let rng = &mut StdRng::seed_from_u64(0xbe11);
    let capacity = 1 << 4;

    // Test: public = zero, constant = zero, selectors = one
    //
    // Compile common circuit descriptions for the prover and verifier
    let q_l = BlsScalar::one();
    let q_r = BlsScalar::one();
    let q_m = BlsScalar::one();
    let q_k = BlsScalar::one();
    let public = BlsScalar::zero();
    let constant = BlsScalar::zero();
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let result = q_l * a + q_r * b + q_m * a * b + q_k * d + public + constant;
    let pi = vec![public, public];
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, a, b, d, public, constant, result);
    let (prover, verifier) = setup(capacity, rng, label, &circuit);

    // Test default works:
    let msg = "Default circuit verification should pass";
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::one();
    let result = q_l * a + q_r * b + q_m * a * b + q_k * d + public + constant;
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, a, b, d, public, constant, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::random(rng);
    let b = BlsScalar::random(rng);
    let d = BlsScalar::random(rng);
    let public = BlsScalar::random(rng);
    let pi = vec![public, public];
    let result = q_l * a + q_r * b + q_m * a * b + q_k * d + public + constant;
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, a, b, d, public, constant, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test unsatisfied circuit:
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::random(rng);
    let b = BlsScalar::random(rng);
    let d = BlsScalar::random(rng);
    let public = BlsScalar::random(rng);
    let result = q_l * a
        + q_r * b
        + q_m * a * b
        + q_k * d
        + public
        + constant
        + BlsScalar::one();
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, a, b, d, public, constant, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test unsatisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::one();
    let public = BlsScalar::one();
    let result = BlsScalar::from(6);
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, a, b, d, public, constant, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test circuit where circuit description doesn't match
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Proof creation of circuit that has different constant than in description should fail";
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let public = BlsScalar::from(2u64);
    let constant = -BlsScalar::from(2u64);
    let result = q_l * a + q_r * b + q_m * a * b + q_k * d + public + constant;
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, a, b, d, public, constant, result);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}
