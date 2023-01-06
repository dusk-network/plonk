// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use zero_crypto::common::{Group, PrimeField};

#[test]
fn decomposition_works() {
    let rng = &mut StdRng::seed_from_u64(8349u64);

    let n = 1 << 10;
    let label = b"demo";
    let pp = PublicParameters::setup(n, rng).expect("failed to create pp");

    pub struct DummyCircuit<const N: usize> {
        a: BlsScalar,
        bits: [BlsScalar; N],
    }

    impl<const N: usize> DummyCircuit<N> {
        pub fn new(a: BlsScalar) -> Self {
            let mut bits = [BlsScalar::zero(); N];

            bits.iter_mut()
                .zip(a.to_bits().iter())
                .for_each(|(b, v)| *b = BlsScalar::from(*v as u64));

            Self { a, bits }
        }
    }

    impl<const N: usize> Default for DummyCircuit<N> {
        fn default() -> Self {
            Self::new(BlsScalar::from(23u64))
        }
    }

    impl<const N: usize> Circuit for DummyCircuit<N> {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);
            let mut w_bits: [Witness; N] = [C::ZERO; N];

            w_bits
                .iter_mut()
                .zip(self.bits.iter())
                .for_each(|(w, b)| *w = composer.append_witness(*b));

            let w_x: [Witness; N] = composer.component_decomposition(w_a);

            w_bits.iter().zip(w_x.iter()).for_each(|(w, b)| {
                composer.assert_equal(*w, *b);
            });

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit<256>>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let a = BlsScalar::random(rng.clone());

        let (proof, public_inputs) = prover
            .prove(rng, &DummyCircuit::<256>::new(a))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // negative works
    {
        let a = BlsScalar::random(rng.clone());

        let mut circuit = DummyCircuit::<256>::new(a);

        circuit.bits[10] = circuit.bits[10] ^ BlsScalar::one();

        prover.prove(rng, &circuit).expect_err("invalid proof");
    }
}
