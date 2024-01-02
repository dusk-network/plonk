// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand_core::OsRng;

// Create a `TestCircuit` struct.
#[derive(Debug, Default)]
pub struct TestCircuit {
    pub a: BlsScalar,
    pub b: BlsScalar,
    pub c: BlsScalar,
    pub d: BlsScalar,
    pub e: JubJubScalar,
    pub f: JubJubAffine,
}

// Implement the 'Circuit' trait that checks:
// 1) a < 2^6
// 2) b < 2^4
// 3) a + b + 42 = c where c is public input
// 4) a * b + d = 42
// 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a Public Input
impl Circuit for TestCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let a = composer.append_witness(self.a);
        let b = composer.append_witness(self.b);
        let d = composer.append_witness(self.d);

        // 1) a < 2^6
        composer.component_range::<3>(a); // 3 BIT_PAIRS = 6 bits

        // 2) b < 2^4
        composer.component_range::<2>(b); // 2 BIT_PAIRS = 4 bits

        // 3) a + b + 42 = c where c is public input
        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .a(a)
            .b(b)
            .constant(BlsScalar::from(42));
        let result = composer.gate_add(constraint);
        let c = composer.append_public(self.c);
        composer.assert_equal(result, c);

        // 4) a * b + d = 42
        let constraint = Constraint::new().mult(1).a(a).b(b).fourth(1).d(d);
        let result = composer.gate_mul(constraint);
        composer.assert_equal_constant(result, BlsScalar::from(42), None);

        // 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a Public Input
        let e = composer.append_witness(self.e);
        let scalar_mul_result = composer
            .component_mul_generator(e, dusk_jubjub::GENERATOR_EXTENDED)?;
        composer.assert_equal_public_point(scalar_mul_result, self.f);

        Ok(())
    }
}

fn main() {
    let label = b"transcript-arguments";
    let pp =
        PublicParameters::setup(1 << 12, &mut OsRng).expect("failed to setup");

    // Compile the default circuit to generate prover and verifier
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("failed to compile circuit");

    // Create the circuit and public inputs to prove
    let a = BlsScalar::from(31);
    let b = BlsScalar::zero();
    let c = BlsScalar::from(73);
    let d = BlsScalar::from(42);
    let e = JubJubScalar::one();
    let f: JubJubAffine = dusk_jubjub::GENERATOR_EXTENDED.into();
    let circuit = TestCircuit { a, b, c, d, e, f };
    let public_inputs = vec![c, f.get_u(), f.get_v()];

    // Generate the proof and its public inputs
    let (proof, pi) =
        prover.prove(&mut OsRng, &circuit).expect("failed to prove");
    assert_eq!(public_inputs, pi);

    // Verify the generated proof
    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}
