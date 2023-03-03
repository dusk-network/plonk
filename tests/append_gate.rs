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
fn append_gate_without_public_and_constant() {
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
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                q_l: BlsScalar::one(),
                q_r: BlsScalar::one(),
                q_m: BlsScalar::one(),
                q_k: BlsScalar::one(),
                q_o: BlsScalar::one(),
                a: BlsScalar::zero(),
                b: BlsScalar::zero(),
                d: BlsScalar::zero(),
                o: BlsScalar::zero(),
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
                .o(w_o);

            composer.append_gate(constraint);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"append_gate_with_constant";
    let rng = &mut StdRng::seed_from_u64(0x1ab);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // Public input vector and wire selectors used by nearly all tests
    let pi = vec![];
    let q_l = BlsScalar::one();
    let q_r = BlsScalar::one();
    let q_m = BlsScalar::one();
    let q_k = BlsScalar::one();
    let q_o = BlsScalar::one();

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::one();
    let o = -BlsScalar::from(4);
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let o = -BlsScalar::one();
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::zero();
    let b = BlsScalar::one();
    let d = BlsScalar::zero();
    let o = -BlsScalar::one();
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::zero();
    let o = -BlsScalar::from(3u64);
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = -BlsScalar::one();
    let b = BlsScalar::zero();
    let d = BlsScalar::one();
    let o = BlsScalar::zero();
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::random(rng);
    let b = BlsScalar::random(rng);
    let d = BlsScalar::random(rng);
    let o = -(a + b + a * b + d);
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    /*
     * FIXME: This circuit has a different circuit description than the one
     * from the prover and verifier.
     * The creation of a proof should therefore fail.
     * See issue #742
    // Test circuit where circuit description doesn't match
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Proof creation of circuit that has different selectors than in description should fail";
    let q_l = BlsScalar::random(rng);
    let q_r = BlsScalar::random(rng);
    let q_m = BlsScalar::random(rng);
    let q_k = BlsScalar::random(rng);
    let q_o = -BlsScalar::random(rng);
    let a = BlsScalar::from(2u64);
    let b = -BlsScalar::from(2u64);
    let d = BlsScalar::from(2u64);
    let o = BlsScalar::from(2u64);
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
    */

    // Test unsatisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::one();
    let b = BlsScalar::one();
    let d = BlsScalar::one();
    let o = BlsScalar::one();
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test unsatisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d = 0
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::random(rng);
    let b = BlsScalar::random(rng);
    let d = BlsScalar::random(rng);
    let o = BlsScalar::random(rng);
    let circuit = TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);
}

#[test]
fn append_gate_with_public_and_constant() {
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

    impl Default for TestCircuit {
        fn default() -> Self {
            Self {
                q_l: BlsScalar::one(),
                q_r: BlsScalar::one(),
                q_m: BlsScalar::one(),
                q_k: BlsScalar::one(),
                q_o: BlsScalar::one(),
                a: BlsScalar::zero(),
                b: BlsScalar::zero(),
                d: BlsScalar::zero(),
                o: BlsScalar::zero(),
                public: BlsScalar::one(),
                constant: -BlsScalar::one(),
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

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"append_gate_with_constant";
    let rng = &mut StdRng::seed_from_u64(0x1ab);
    let capacity = 1 << 4;
    let (prover, verifier) = setup(capacity, rng, label);

    // Wire selectors and constant as they are in the circuit description used
    // by (nearly) all tests
    let q_l = BlsScalar::one();
    let q_r = BlsScalar::one();
    let q_m = BlsScalar::one();
    let q_k = BlsScalar::one();
    let q_o = BlsScalar::one();
    let constant = -BlsScalar::one();

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![BlsScalar::one()];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d + q_c + PI = 0
    let msg = "Satisfied circuit should pass";
    let a = -BlsScalar::one();
    let b = BlsScalar::one();
    let d = -BlsScalar::from(2);
    let o = BlsScalar::one();
    let public = BlsScalar::from(3);
    let pi = vec![public.clone()];
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test satisfied circuit:
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d + q_c + PI = 0
    let msg = "Satisfied circuit with different public input and constant value from circuit description should pass";
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let o = BlsScalar::one();
    let public = BlsScalar::zero();
    let pi = vec![public.clone()];
    let constant = BlsScalar::zero();
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test circuit where circuit description doesn't match should still passes
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d + q_c + PI = 0
    let msg = "Proof creation of circuit that has different selectors than in description should pass";
    let q_l = BlsScalar::zero();
    let q_r = BlsScalar::zero();
    let q_m = BlsScalar::zero();
    let q_k = BlsScalar::zero();
    let q_o = BlsScalar::zero();
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let o = BlsScalar::zero();
    let public = BlsScalar::one();
    let pi = vec![public.clone()];
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, rng, &msg);

    // Test circuit where circuit description doesn't match
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d + q_c + PI = 0
    let msg = "Proof creation of circuit that has different constant than in description should fail";
    let constant = -BlsScalar::from(2u64);
    let a = BlsScalar::zero();
    let b = BlsScalar::zero();
    let d = BlsScalar::zero();
    let o = BlsScalar::zero();
    let public = BlsScalar::from(2u64);
    let circuit =
        TestCircuit::new(q_l, q_r, q_m, q_k, q_o, a, b, d, o, public, constant);
    check_unsatisfied_circuit(&prover, &circuit, rng, &msg);

    // Test unsatisfied circuit
    // q_m·a·b + q_l·a + q_r·b + q_o·o + q_4·d + q_c + PI != 0
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
