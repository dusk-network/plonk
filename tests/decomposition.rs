// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

mod common;
use common::{check_satisfied_circuit, check_unsatisfied_circuit};

#[test]
fn component_decomposition() {
    pub struct TestCircuit<const N: usize> {
        a: BlsScalar,
        decomp_expected: [BlsScalar; N],
    }

    impl<const N: usize> TestCircuit<N> {
        pub fn new(a: BlsScalar, decomp_expected: [BlsScalar; N]) -> Self {
            Self { a, decomp_expected }
        }
    }

    impl<const N: usize> Default for TestCircuit<N> {
        fn default() -> Self {
            Self::new(BlsScalar::zero(), [BlsScalar::zero(); N])
        }
    }

    impl<const N: usize> Circuit for TestCircuit<N> {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_a = composer.append_witness(self.a);
            let decomp_circuit: [Witness; N] =
                composer.component_decomposition(w_a);

            decomp_circuit.iter().zip(self.decomp_expected).for_each(
                |(bit_circuit, bit_expected)| {
                    let w_bit_expected = composer.append_witness(bit_expected);
                    composer.assert_equal(*bit_circuit, w_bit_expected);
                },
            );

            Ok(())
        }
    }

    let label = b"component_decomposition";
    let mut rng = StdRng::seed_from_u64(0x1ea);
    let capacity = 1 << 10;
    let pi = vec![];

    // Test N = 1
    //
    // Compile new circuit descriptions for the prover and verifier
    const N1: usize = 1;
    let circuit = TestCircuit::<N1>::default();
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit<N1>>(&pp, label)
        .expect("Circuit should compile");

    // Test default works:
    let msg = "Default circuit verification should pass";
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test bls one
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::one();
    let mut decomp_expected = [BlsScalar::zero(); N1];
    decomp_expected[0] = BlsScalar::one();
    let circuit = TestCircuit::new(a, decomp_expected);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test bls two fails
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::from(2);
    let decomp_expected = [BlsScalar::zero(); N1];
    let circuit = TestCircuit::new(a, decomp_expected);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test N = 64
    //
    // Compile new circuit descriptions for the prover and verifier
    const N64: usize = 64;
    let circuit = TestCircuit::<N64>::default();
    let (prover, verifier) =
        Compiler::compile_with_circuit(&pp, label, &circuit)
            .expect("Circuit should compile");

    // Test default works:
    let msg = "Default circuit verification should pass";
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test bls two
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::from(2);
    let mut decomp_expected = [BlsScalar::zero(); N64];
    decomp_expected[1] = BlsScalar::one();
    let circuit = TestCircuit::new(a, decomp_expected);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test bls forty two
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::from(42);
    let mut decomp_expected = [BlsScalar::zero(); N64];
    decomp_expected[5] = BlsScalar::one();
    decomp_expected[3] = BlsScalar::one();
    decomp_expected[1] = BlsScalar::one();
    let circuit = TestCircuit::new(a, decomp_expected);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test u64::MAX
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::from(u64::MAX);
    let decomp_expected = [BlsScalar::one(); N64];
    let circuit = TestCircuit::new(a, decomp_expected);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test 2 * u64::MAX + 1 fails
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::from(u64::MAX) * BlsScalar::from(2) + BlsScalar::one();
    let decomp_expected = [BlsScalar::one(); N64];
    let circuit = TestCircuit::new(a, decomp_expected);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);

    // Test N = 64
    //
    // Compile new circuit descriptions for the prover and verifier
    const N256: usize = 256;
    let circuit = TestCircuit::<N256>::default();
    let (prover, verifier) =
        Compiler::compile_with_circuit(&pp, label, &circuit)
            .expect("Circuit should compile");

    // Test random works:
    let msg = "Verification of satisfied circuit should pass";
    let a = BlsScalar::random(&mut rng);
    let mut decomp_expected = [BlsScalar::zero(); N256];
    a.to_bits().iter().enumerate().for_each(|(i, bit)| {
        decomp_expected[i] = BlsScalar::from(*bit as u64);
    });
    let circuit = TestCircuit::new(a, decomp_expected);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, &msg);

    // Test flipping one bit fails
    let msg = "Proof creation of unsatisfied circuit should fail";
    let a = BlsScalar::random(&mut rng);
    let mut decomp_expected = [BlsScalar::zero(); N256];
    a.to_bits().iter().enumerate().for_each(|(i, bit)| {
        decomp_expected[i] = BlsScalar::from(*bit as u64);
    });
    decomp_expected[123] *= -BlsScalar::one();
    decomp_expected[123] += BlsScalar::one();
    let circuit = TestCircuit::new(a, decomp_expected);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, &msg);
}
