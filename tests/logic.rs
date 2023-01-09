// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use rand::rngs::StdRng;
use rand::SeedableRng;
use zero_crypto::behave::Group;
use zero_plonk::prelude::*;

#[test]
fn logic_and_works() {
    let mut rng = StdRng::seed_from_u64(8349u64);

    let n = 1 << 8;
    let label = b"demo";
    let pp = PublicParameters::setup(n, &mut rng).expect("failed to create pp");

    pub struct DummyCircuit {
        a: BlsScalar,
        b: BlsScalar,
        c: BlsScalar,
        bits: usize,
    }

    impl DummyCircuit {
        pub fn new(a: BlsScalar, b: BlsScalar, bits: usize) -> Self {
            let x = BlsScalar::pow_of_2(bits as u64) - BlsScalar::one();

            let a = a & x;
            let b = b & x;
            let c = a & b & x;

            Self { a, b, c, bits }
        }
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            Self::new(7u64.into(), 8u64.into(), 256)
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_witness(self.b);
            let w_c = composer.append_witness(self.c);

            let w_x = composer.append_logic_and(w_a, w_b, self.bits);

            composer.assert_equal(w_c, w_x);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(a, b, 256))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // negative works
    {
        let bits = 256;

        let x = BlsScalar::pow_of_2(bits as u64) - BlsScalar::one();

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let a = a & x;
        let b = b & x;
        let c = a & b & x;

        let m = BlsScalar::random(&mut rng) & x;
        let n = a & m & x;

        assert_ne!(c, n);

        prover
            .prove(&mut rng, &DummyCircuit { a, b, c: n, bits })
            .expect_err("the provided proof isn't valid");
    }

    // small bits works
    {
        let bits = 30;

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let circuit = DummyCircuit::new(a, b, bits);

        let (prover, verifier) =
            Compiler::compile_with_circuit(&pp, label, &circuit)
                .expect("failed to compile circuit");

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(a, b, bits))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // zero bits works
    {
        let bits = 0;

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let circuit = DummyCircuit::new(a, b, bits);

        let (prover, verifier) =
            Compiler::compile_with_circuit(&pp, label, &circuit)
                .expect("failed to compile circuit");

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(a, b, bits))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // odd bits will compile
    {
        let bits = 55;

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let circuit = DummyCircuit::new(a, b, bits);

        Compiler::compile_with_circuit(&pp, label, &circuit)
            .expect("failed to compile circuit");
    }
}

#[test]
fn logic_xor_works() {
    let mut rng = StdRng::seed_from_u64(8349u64);

    let n = 1 << 8;
    let label = b"demo";
    let pp = PublicParameters::setup(n, &mut rng).expect("failed to create pp");

    pub struct DummyCircuit {
        a: BlsScalar,
        b: BlsScalar,
        c: BlsScalar,
        bits: usize,
    }

    impl DummyCircuit {
        pub fn new(a: BlsScalar, b: BlsScalar, bits: usize) -> Self {
            let x = BlsScalar::pow_of_2(bits as u64) - BlsScalar::one();

            let a = a & x;
            let b = b & x;
            let c = (a ^ b) & x;

            Self { a, b, c, bits }
        }
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            Self::new(7u64.into(), 8u64.into(), 256)
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_witness(self.b);
            let w_c = composer.append_witness(self.c);

            let w_x = composer.append_logic_xor(w_a, w_b, self.bits);

            composer.assert_equal(w_c, w_x);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(a, b, 256))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // negative works
    {
        let bits = 256;

        let x = BlsScalar::pow_of_2(bits as u64) - BlsScalar::one();

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let a = a & x;
        let b = b & x;
        let c = (a ^ b) & x;

        let m = BlsScalar::random(&mut rng) & x;
        let n = (a ^ m) & x;

        assert_ne!(c, n);

        prover
            .prove(&mut rng, &DummyCircuit { a, b, c: n, bits })
            .expect_err("the provided proof isn't valid");
    }

    // small bits works
    {
        let bits = 30;

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let circuit = DummyCircuit::new(a, b, bits);

        let (prover, verifier) =
            Compiler::compile_with_circuit(&pp, label, &circuit)
                .expect("failed to compile circuit");

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(a, b, bits))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // zero bits works
    {
        let bits = 0;

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let circuit = DummyCircuit::new(a, b, bits);

        let (prover, verifier) =
            Compiler::compile_with_circuit(&pp, label, &circuit)
                .expect("failed to compile circuit");

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(a, b, bits))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // odd bits will compile
    {
        let bits = 55;

        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);

        let circuit = DummyCircuit::new(a, b, bits);

        Compiler::compile_with_circuit(&pp, label, &circuit)
            .expect("failed to compile circuit");
    }
}
