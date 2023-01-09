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
fn mul_generator_works() {
    let mut rng = StdRng::seed_from_u64(8349u64);

    let n = 1 << 9;
    let label = b"demo";
    let pp = PublicParameters::setup(n, &mut rng).expect("failed to create pp");

    pub struct DummyCircuit {
        a: JubJubScalar,
        b: JubJubExtended,
    }

    impl DummyCircuit {
        pub fn new(a: JubJubScalar) -> Self {
            Self {
                a,
                b: zero_jubjub::GENERATOR_EXTENDED * &a,
            }
        }
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            Self::new(JubJubScalar::from(7u64))
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_point(self.b);

            let w_x = composer.component_mul_generator(
                w_a,
                zero_jubjub::GENERATOR_EXTENDED,
            )?;

            composer.assert_equal_point(w_b, w_x);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let a = JubJubScalar::random(&mut rng);
        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(a))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // negative check
    {
        let a = JubJubScalar::from(7u64);
        let b = zero_jubjub::GENERATOR_EXTENDED * &a;

        let x = JubJubScalar::from(8u64);
        let y = zero_jubjub::GENERATOR_EXTENDED * &x;

        assert_ne!(b, y);

        prover
            .prove(&mut rng, &DummyCircuit { a, b: y })
            .expect_err("invalid ecc proof isn't feasible");
    }

    // invalid jubjub won't panic
    {
        let a = -BlsScalar::one();
        let a = JubJubScalar::to_mont_form(a.0);

        let x = JubJubScalar::from(8u64);
        let y = zero_jubjub::GENERATOR_EXTENDED * &x;

        prover
            .prove(&mut rng, &DummyCircuit { a, b: y })
            .expect_err("invalid ecc proof isn't feasible");
    }
}

#[test]
fn add_point_works() {
    let mut rng = StdRng::seed_from_u64(8349u64);

    let n = 1 << 4;
    let label = b"demo";
    let pp = PublicParameters::setup(n, &mut rng).expect("failed to create pp");

    pub struct DummyCircuit {
        a: JubJubExtended,
        b: JubJubExtended,
        c: JubJubExtended,
    }

    impl DummyCircuit {
        pub fn new(a: &JubJubScalar, b: &JubJubScalar) -> Self {
            let a = zero_jubjub::GENERATOR_EXTENDED * a;
            let b = zero_jubjub::GENERATOR_EXTENDED * b;
            let c = a + b;

            Self { a, b, c }
        }
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            Self::new(&JubJubScalar::from(7u64), &JubJubScalar::from(8u64))
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_point(self.a);
            let w_b = composer.append_point(self.b);
            let w_c = composer.append_point(self.c);

            let w_x = composer.component_add_point(w_a, w_b);

            composer.assert_equal_point(w_c, w_x);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let a = JubJubScalar::random(&mut rng);
        let b = JubJubScalar::random(&mut rng);

        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(&a, &b))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // identity works
    {
        let a = JubJubScalar::random(&mut rng);
        let a = zero_jubjub::GENERATOR_EXTENDED * &a;

        let (proof, public_inputs) = prover
            .prove(
                &mut rng,
                &DummyCircuit {
                    a,
                    b: JubJubExtended::identity(),
                    c: a,
                },
            )
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // zero works
    {
        let (proof, public_inputs) = prover
            .prove(
                &mut rng,
                &DummyCircuit {
                    a: JubJubExtended::identity(),
                    b: JubJubExtended::identity(),
                    c: JubJubExtended::identity(),
                },
            )
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // negative check
    {
        let a = JubJubScalar::from(7u64);
        let a = zero_jubjub::GENERATOR_EXTENDED * &a;

        let b = JubJubScalar::from(8u64);
        let b = zero_jubjub::GENERATOR_EXTENDED * &b;

        let c = JubJubScalar::from(9u64);
        let c = zero_jubjub::GENERATOR_EXTENDED * &c;

        assert_ne!(c, a + b);

        prover
            .prove(&mut rng, &DummyCircuit { a, b, c })
            .expect_err("invalid ecc proof isn't feasible");
    }
}

#[test]
#[ignore]
fn mul_point_works() {
    let mut rng = StdRng::seed_from_u64(8349u64);

    let n = 1 << 13;
    let label = b"demo";
    let pp = PublicParameters::setup(n, &mut rng).expect("failed to create pp");

    pub struct DummyCircuit {
        a: JubJubScalar,
        b: JubJubExtended,
        c: JubJubExtended,
    }

    impl DummyCircuit {
        pub fn new(a: JubJubScalar, b: JubJubExtended) -> Self {
            let c = b * &a;

            Self { a, b, c }
        }
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            let b = JubJubScalar::from(8u64);
            let b = zero_jubjub::GENERATOR_EXTENDED * &b;

            Self::new(JubJubScalar::from(7u64), b)
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_point(self.b);
            let w_c = composer.append_point(self.c);

            let w_x = composer.component_mul_point(w_a, w_b);

            composer.assert_equal_point(w_c, w_x);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let a = JubJubScalar::random(&mut rng);
        let b = JubJubScalar::random(&mut rng);
        let b = zero_jubjub::GENERATOR_EXTENDED * &b;

        let (proof, public_inputs) = prover
            .prove(&mut rng, &DummyCircuit::new(a, b))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // negative works
    {
        let a = JubJubScalar::random(&mut rng);
        let b = JubJubScalar::random(&mut rng);
        let b = zero_jubjub::GENERATOR_EXTENDED * &b;
        let c = b * &a;

        let x = JubJubScalar::random(&mut rng);
        let x = zero_jubjub::GENERATOR_EXTENDED * &x;

        assert_ne!(c, x);

        prover
            .prove(&mut rng, &DummyCircuit { a, b, c: x })
            .expect_err("circuit is not satisfied");
    }
}
