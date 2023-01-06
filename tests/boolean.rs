// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn boolean_works() {
    let rng = &mut StdRng::seed_from_u64(8349u64);

    let n = 1 << 4;
    let label = b"demo";
    let pp = PublicParameters::setup(n, rng).expect("failed to create pp");

    pub struct DummyCircuit {
        a: BlsScalar,
    }

    impl DummyCircuit {
        pub fn new(a: BlsScalar) -> Self {
            Self { a }
        }
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            Self::new(1u64.into())
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);

            composer.component_boolean(w_a);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let a = BlsScalar::one();

        let (proof, public_inputs) = prover
            .prove(rng, &DummyCircuit::new(a))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");

        let a = BlsScalar::zero();

        let (proof, public_inputs) = prover
            .prove(rng, &DummyCircuit::new(a))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // negative works
    {
        let a = BlsScalar::from(2u64);

        prover
            .prove(rng, &DummyCircuit::new(a))
            .expect_err("invalid circuit");
    }
}

#[test]
fn select_works() {
    let rng = &mut StdRng::seed_from_u64(8349u64);

    let n = 1 << 6;
    let label = b"demo";
    let pp = PublicParameters::setup(n, rng).expect("failed to create pp");

    #[derive(Clone)]
    pub struct DummyCircuit {
        bit: BlsScalar,
        a: BlsScalar,
        b: BlsScalar,
        res: BlsScalar,

        zero_bit: BlsScalar,
        zero_a: BlsScalar,
        zero_res: BlsScalar,

        one_bit: BlsScalar,
        one_a: BlsScalar,
        one_res: BlsScalar,

        point_bit: BlsScalar,
        point_a: JubJubExtended,
        point_b: JubJubExtended,
        point_res: JubJubExtended,

        identity_bit: BlsScalar,
        identity_a: JubJubExtended,
        identity_res: JubJubExtended,
    }

    impl DummyCircuit {
        pub fn new(
            bit: BlsScalar,
            a: BlsScalar,
            b: BlsScalar,
            zero_bit: BlsScalar,
            zero_a: BlsScalar,
            one_bit: BlsScalar,
            one_a: BlsScalar,
            point_bit: BlsScalar,
            point_a: JubJubExtended,
            point_b: JubJubExtended,
            identity_bit: BlsScalar,
            identity_a: JubJubExtended,
        ) -> Self {
            let res = if bit == BlsScalar::one() { a } else { b };

            let zero_res = if zero_bit == BlsScalar::one() {
                zero_a
            } else {
                BlsScalar::zero()
            };

            let one_res = if one_bit == BlsScalar::one() {
                one_a
            } else {
                BlsScalar::one()
            };

            let point_res = if one_bit == BlsScalar::one() {
                point_a
            } else {
                point_b
            };

            let identity_res = if identity_bit == BlsScalar::one() {
                identity_a
            } else {
                JubJubExtended::identity()
            };

            Self {
                bit,
                a,
                b,
                res,
                zero_bit,
                zero_a,
                zero_res,
                one_bit,
                one_a,
                one_res,
                point_bit,
                point_a,
                point_b,
                point_res,
                identity_bit,
                identity_a,
                identity_res,
            }
        }
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            let bit = BlsScalar::one();
            let a = BlsScalar::from(3u64);
            let b = BlsScalar::from(5u64);
            let zero_bit = BlsScalar::zero();
            let zero_a = BlsScalar::from(7u64);
            let one_bit = BlsScalar::one();
            let one_a = BlsScalar::from(11u64);
            let point_bit = BlsScalar::zero();
            let point_a =
                zero_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(13u64);
            let point_b =
                zero_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(17u64);
            let identity_bit = BlsScalar::one();
            let identity_a =
                zero_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(19u64);

            Self::new(
                bit,
                a,
                b,
                zero_bit,
                zero_a,
                one_bit,
                one_a,
                point_bit,
                point_a,
                point_b,
                identity_bit,
                identity_a,
            )
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_bit = composer.append_witness(self.bit);
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_witness(self.b);
            let w_res = composer.append_witness(self.res);
            let w_zero_bit = composer.append_witness(self.zero_bit);
            let w_zero_a = composer.append_witness(self.zero_a);
            let w_zero_res = composer.append_witness(self.zero_res);
            let w_one_bit = composer.append_witness(self.one_bit);
            let w_one_a = composer.append_witness(self.one_a);
            let w_one_res = composer.append_witness(self.one_res);
            let w_point_bit = composer.append_witness(self.point_bit);
            let w_point_a = composer.append_point(self.point_a);
            let w_point_b = composer.append_point(self.point_b);
            let w_point_res = composer.append_point(self.point_res);
            let w_identity_bit = composer.append_witness(self.identity_bit);
            let w_identity_a = composer.append_point(self.identity_a);
            let w_identity_res = composer.append_point(self.identity_res);

            let w_x = composer.component_select(w_bit, w_a, w_b);
            composer.assert_equal(w_x, w_res);

            let w_zero_x = composer.component_select_zero(w_zero_bit, w_zero_a);
            composer.assert_equal(w_zero_x, w_zero_res);

            let w_one_x = composer.component_select_one(w_one_bit, w_one_a);
            composer.assert_equal(w_one_x, w_one_res);

            let w_point_x = composer.component_select_point(
                w_point_bit,
                w_point_a,
                w_point_b,
            );
            composer.assert_equal_point(w_point_x, w_point_res);

            let w_identity_x = composer
                .component_select_identity(w_identity_bit, w_identity_a);
            composer.assert_equal_point(w_identity_x, w_identity_res);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let bit = BlsScalar::one();

        let a = BlsScalar::random(rng);
        let b = BlsScalar::random(rng);
        let zero_bit = bit;
        let zero_a = BlsScalar::random(rng);
        let one_bit = bit;
        let one_a = BlsScalar::random(rng);
        let point_bit = bit;
        let point_a = JubJubScalar::random(rng);
        let point_a = zero_jubjub::GENERATOR_EXTENDED * &point_a;
        let point_b = JubJubScalar::random(rng);
        let point_b = zero_jubjub::GENERATOR_EXTENDED * &point_b;
        let identity_bit = bit;
        let identity_a = JubJubScalar::random(rng);
        let identity_a = zero_jubjub::GENERATOR_EXTENDED * &identity_a;

        let circuit = DummyCircuit::new(
            bit,
            a,
            b,
            zero_bit,
            zero_a,
            one_bit,
            one_a,
            point_bit,
            point_a,
            point_b,
            identity_bit,
            identity_a,
        );

        let (proof, public_inputs) =
            prover.prove(rng, &circuit).expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");

        let bit = BlsScalar::zero();

        let a = BlsScalar::random(rng);
        let b = BlsScalar::random(rng);
        let zero_bit = bit;
        let zero_a = BlsScalar::random(rng);
        let one_bit = bit;
        let one_a = BlsScalar::random(rng);
        let point_bit = bit;
        let point_a = JubJubScalar::random(rng);
        let point_a = zero_jubjub::GENERATOR_EXTENDED * &point_a;
        let point_b = JubJubScalar::random(rng);
        let point_b = zero_jubjub::GENERATOR_EXTENDED * &point_b;
        let identity_bit = bit;
        let identity_a = JubJubScalar::random(rng);
        let identity_a = zero_jubjub::GENERATOR_EXTENDED * &identity_a;

        let circuit = DummyCircuit::new(
            bit,
            a,
            b,
            zero_bit,
            zero_a,
            one_bit,
            one_a,
            point_bit,
            point_a,
            point_b,
            identity_bit,
            identity_a,
        );

        let (proof, public_inputs) =
            prover.prove(rng, &circuit).expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    let bit = BlsScalar::one();

    let a = BlsScalar::random(rng);
    let b = BlsScalar::random(rng);
    let zero_bit = bit;
    let zero_a = BlsScalar::random(rng);
    let one_bit = bit;
    let one_a = BlsScalar::random(rng);
    let point_bit = bit;
    let point_a = JubJubScalar::random(rng);
    let point_a = zero_jubjub::GENERATOR_EXTENDED * &point_a;
    let point_b = JubJubScalar::random(rng);
    let point_b = zero_jubjub::GENERATOR_EXTENDED * &point_b;
    let identity_bit = bit;
    let identity_a = JubJubScalar::random(rng);
    let identity_a = zero_jubjub::GENERATOR_EXTENDED * &identity_a;

    let base = DummyCircuit::new(
        bit,
        a,
        b,
        zero_bit,
        zero_a,
        one_bit,
        one_a,
        point_bit,
        point_a,
        point_b,
        identity_bit,
        identity_a,
    );

    // negative select works
    {
        let mut circuit = base.clone();

        circuit.res = -circuit.res;

        prover.prove(rng, &circuit).expect_err("invalid proof");
    }

    // negative select zero works
    {
        let mut circuit = base.clone();

        circuit.zero_res = -circuit.zero_res;

        prover.prove(rng, &circuit).expect_err("invalid proof");
    }

    // negative select one works
    {
        let mut circuit = base.clone();

        circuit.one_res = -circuit.one_res;

        prover.prove(rng, &circuit).expect_err("invalid proof");
    }

    // negative select point works
    {
        let mut circuit = base.clone();

        let x = zero_jubjub::GENERATOR_EXTENDED * &JubJubScalar::one();

        circuit.point_res = circuit.point_res + x;

        prover.prove(rng, &circuit).expect_err("invalid proof");
    }

    // negative select identity works
    {
        let mut circuit = base.clone();

        let x = zero_jubjub::GENERATOR_EXTENDED * &JubJubScalar::one();

        circuit.identity_res = circuit.identity_res + x;

        prover.prove(rng, &circuit).expect_err("invalid proof");
    }
}
