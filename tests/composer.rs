// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[test]
fn circuit_with_all_gates() {
    let rng = &mut StdRng::seed_from_u64(8349u64);

    let n = 1 << 12;
    let label = b"demo";
    let pp = PublicParameters::setup(n, rng).expect("failed to create pp");

    pub struct DummyCircuit {
        a: BlsScalar,
        b: BlsScalar,
        x: BlsScalar,
        y: JubJubScalar,
        z: JubJubExtended,
    }

    impl Default for DummyCircuit {
        fn default() -> Self {
            Self {
                a: BlsScalar::from(2u64),
                b: BlsScalar::from(3u64),
                x: BlsScalar::from(6u64),
                y: JubJubScalar::from(7u64),
                z: dusk_jubjub::GENERATOR_EXTENDED * &JubJubScalar::from(7u64),
            }
        }
    }

    impl Circuit for DummyCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_a = composer.append_witness(self.a);
            let w_b = composer.append_witness(self.b);
            let w_x = composer.append_witness(self.x);
            let w_y = composer.append_witness(self.y);
            let w_z = composer.append_point(self.z)?;

            let s = Constraint::new().mult(1).a(w_a).b(w_b);

            let r_w = composer.gate_mul(s);

            composer.append_constant(15);
            composer.append_constant_point(self.z)?;
            composer.append_public_point(self.z)?;
            composer.append_public(self.y);

            composer.assert_equal(w_x, r_w);
            composer.assert_equal_constant(w_x, 0, Some(self.x));
            composer.assert_equal_point(w_z, w_z);
            composer.assert_equal_public_point(w_z, self.z)?;

            composer.gate_add(Constraint::new().left(1).right(1).a(w_a).b(w_b));

            // `z` is a multiple of the prime-order generator, so subgroup
            // membership holds by construction.
            let tf_z = TorsionFreeWitnessPoint::new_unchecked(w_z);
            composer.component_add_point(tf_z, tf_z);
            composer.append_logic_and::<127>(w_a, w_b);
            composer.component_boolean(Composer::ONE);
            composer.component_decomposition::<254>(w_a);
            composer.component_mul_generator(
                w_y,
                dusk_jubjub::GENERATOR_EXTENDED,
            )?;
            composer.component_mul_point(w_y, tf_z);
            composer.component_range_bits::<256>(w_a);
            composer.component_select(Composer::ONE, w_a, w_b);
            composer.component_select_identity(Composer::ONE, tf_z);
            composer.component_select_one(Composer::ONE, w_a);
            composer.component_select_point(Composer::ONE, w_z, w_z);
            composer.component_select_zero(Composer::ONE, w_a);
            composer.append_logic_xor::<127>(w_a, w_b);

            Ok(())
        }
    }

    let (prover, verifier) = Compiler::compile::<DummyCircuit>(&pp, label)
        .expect("failed to compile circuit");

    let compressed =
        DummyCircuit::compress().expect("failed to compress circuit");

    let mut packed = miniz_oxide::inflate::decompress_to_vec(&compressed)
        .expect("failed to decompress circuit");
    packed.push(0xc0); // valid msgpack nil value after the circuit payload
    let compressed_with_trailing_data =
        miniz_oxide::deflate::compress_to_vec(&packed, 10);
    assert!(matches!(
        Compiler::compile_with_compressed(
            &pp,
            label,
            &compressed_with_trailing_data
        ),
        Err(Error::InvalidCompressedCircuit)
    ));

    let (decompressed_prover, decompressed_verifier) =
        Compiler::compile_with_compressed(&pp, label, &compressed).unwrap();

    let decoded_prover_bytes = decompressed_prover.to_bytes();
    let len = prover.serialized_size();
    let prover = prover.to_bytes();

    assert_eq!(prover.len(), len);
    assert_eq!(decoded_prover_bytes, prover);

    let (proof, public_inputs) = decompressed_prover
        .prove(rng, &DummyCircuit::default())
        .expect("failed to prove");

    decompressed_verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    let prover =
        Prover::try_from_bytes(&prover).expect("failed to deserialize prover");

    let len = verifier.serialized_size();
    let verifier = verifier.to_bytes();

    assert_eq!(verifier.len(), len);

    let verifier = Verifier::try_from_bytes(&verifier)
        .expect("failed to deserialize verifier");

    let (proof, public_inputs) = prover
        .prove(rng, &DummyCircuit::default())
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}
