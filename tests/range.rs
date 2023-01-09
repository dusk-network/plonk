// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use rand::rngs::StdRng;
use rand::SeedableRng;
use zero_plonk::prelude::*;

#[test]
fn range_works() {
    let rng = &mut StdRng::seed_from_u64(8349u64);

    let n = 1 << 5;
    let label = b"demo";
    let pp = PublicParameters::setup(n, rng).expect("failed to create pp");

    const DEFAULT_BITS: usize = 76;

    pub struct DummyCircuit {
        a: BlsScalar,
        bits: usize,
    }

    impl DummyCircuit {
        pub fn new(a: BlsScalar, bits: usize) -> Self {
            Self { a, bits }
        }
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            Self::new(7u64.into(), DEFAULT_BITS)
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
        where
            C: Composer,
        {
            let w_a = composer.append_witness(self.a);

            composer.component_range(w_a, self.bits);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // default works
    {
        let a = BlsScalar::from(u64::MAX);

        let (proof, public_inputs) = prover
            .prove(rng, &DummyCircuit::new(a, DEFAULT_BITS))
            .expect("failed to prove");

        verifier
            .verify(&proof, &public_inputs)
            .expect("failed to verify proof");
    }

    // negative works
    {
        let a = -BlsScalar::pow_of_2(DEFAULT_BITS as u64 + 1);

        prover
            .prove(rng, &DummyCircuit::new(a, DEFAULT_BITS))
            .expect_err("bits aren't in range");
    }

    // odd bits won't panic
    {
        let a = BlsScalar::one();

        Compiler::compile_with_circuit::<DummyCircuit>(
            &pp,
            label,
            &DummyCircuit::new(a, DEFAULT_BITS + 1),
        )
        .expect("failed to compile circuit");
    }
}
