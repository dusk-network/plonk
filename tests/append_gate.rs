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
fn append_gate() {
    #[derive(Default)]
    pub struct TestCircuit {
        q_l: BlsScalar,
        q_r: BlsScalar,
        q_m: BlsScalar,
        q_k: BlsScalar,
        q_o: BlsScalar,
        a: BlsScalar,
        b: BlsScalar,
        d: BlsScalar,
        o: BlsScalar,
        public: BlsScalar,
        constant: BlsScalar,
    }

    impl TestCircuit {
        pub fn new(
            q_l: BlsScalar,
            q_r: BlsScalar,
            q_m: BlsScalar,
            q_k: BlsScalar,
            q_o: BlsScalar,
            a: BlsScalar,
            b: BlsScalar,
            d: BlsScalar,
            o: BlsScalar,
            public: BlsScalar,
            constant: BlsScalar,
        ) -> Self {
            Self {
                q_l,
                q_r,
                q_m,
                q_k,
                q_o,
                a,
                b,
                d,
                o,
                public,
                constant,
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
            let w_o = composer.append_witness(self.o);

            let constraint = Constraint::new()
                .left(self.q_l)
                .right(self.q_r)
                .mult(self.q_m)
                .fourth(self.q_k)
                .output(self.q_o)
                .a(w_a)
                .b(w_b)
                .d(w_d)
                .o(w_o)
                .public(self.public)
                .constant(self.constant);

            composer.append_gate(constraint);

            Ok(())
        }
    }

    let label = b"append_gate_with_constant";
    let rng = &mut StdRng::seed_from_u64(0x1ab);
    let capacity = 1 << 4;

    // Test: public = zero, constant = zero, selectors = one
    //
    // Compile common circuit descriptions for the prover and verifier
    let q_l = BlsScalar::one();
    let q_r = BlsScalar::one();
    let q_m = BlsScalar::one();
    let q_k = BlsScalar::one();
    let q_o = BlsScalar::one();
    let public = BlsScalar::zero();
    let constant = BlsScalar::zero();
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let o = BlsScalar::zero();
    let pi = vec![public];
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
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
    let o = -BlsScalar::from(4);
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let o = -BlsScalar::one();
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::zero();
    let b = BlsScalar::one();
    let d = BlsScalar::zero();
    let o = -BlsScalar::one();
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::zero();
    let o = -BlsScalar::from(3u64);
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = -BlsScalar::one();
    let b = BlsScalar::zero();
    let d = BlsScalar::one();
    let o = BlsScalar::zero();
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::random(rng);
    let b = BlsScalar::random(rng);
    let d = BlsScalar::random(rng);
    let public = BlsScalar::from(42);
    let o = -(a + b + a * b + d + public);
    let pi = vec![public];
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test unsatisfied circuit:
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::random(rng);
    let b = BlsScalar::random(rng);
    let d = BlsScalar::random(rng);
    let o = BlsScalar::random(rng);
    let public = BlsScalar::random(rng);
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test unsatisfied circuit:
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::one();
    let o = BlsScalar::one();
    let public = BlsScalar::one();
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test circuit where circuit description doesn't match
    // q_l·a + q_r·b + q_m·a·b + q_o·o + q_4·d + public + constant = 0
    let msg = "Proof creation of circuit that has different constant than in description should fail";
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let o = BlsScalar::zero();
    let public = BlsScalar::from(2u64);
    let constant = -BlsScalar::from(2u64);
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test unsatisfied circuit
    let msg = "Verification of unsatisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::one();
    let o = BlsScalar::one();
    let public = BlsScalar::one();
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}
