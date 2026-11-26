// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
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
                z: dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(7u64),
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

    // Independent all-gate proof digests pinned against `master` (`750d38d`),
    // covering arithmetic, range, logic (AND/XOR), fixed-base ECC,
    // variable-base ECC, permutation, and public inputs under both `std` and
    // `--no-default-features --features alloc`.
    let expected_digest_1 = [
        0x07, 0x51, 0x67, 0xdc, 0x01, 0x1d, 0x58, 0xf2, 0xa9, 0x97, 0xad, 0x29,
        0xa0, 0x88, 0xc6, 0x27, 0xff, 0x29, 0x76, 0x8b, 0x09, 0x4d, 0xe7, 0xe9,
        0x82, 0x72, 0x3d, 0xe9, 0x55, 0x25, 0x54, 0x97, 0xa4, 0x3a, 0x3e, 0xb1,
        0x76, 0x25, 0xd8, 0x04, 0x93, 0x3c, 0x2d, 0x20, 0x71, 0x53, 0x3d, 0x75,
        0xec, 0x43, 0xac, 0xc3, 0xa2, 0xa0, 0xca, 0x45, 0x89, 0x82, 0x86, 0x14,
        0x68, 0xc1, 0x38, 0xa6,
    ];
    assert_eq!(
        blake2b_simd::blake2b(&proof.to_bytes()).as_array(),
        &expected_digest_1
    );

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

    let expected_digest_2 = [
        0x24, 0xeb, 0xa4, 0x5f, 0xcf, 0xaf, 0x27, 0x5e, 0x63, 0x06, 0xb9, 0xf1,
        0x22, 0xa3, 0xad, 0x0f, 0x1b, 0x11, 0x55, 0x38, 0x4c, 0x9d, 0x26, 0x70,
        0x87, 0x2b, 0x87, 0xeb, 0x5a, 0x9b, 0x7b, 0xfd, 0x0a, 0x48, 0x4b, 0xbd,
        0x00, 0x00, 0x0e, 0xba, 0x55, 0xf2, 0x02, 0xfe, 0xbc, 0x4f, 0x83, 0xfa,
        0x78, 0x85, 0xa7, 0x4d, 0xab, 0x1c, 0x88, 0xc0, 0xe3, 0xdb, 0x38, 0x6f,
        0x19, 0x6c, 0xaf, 0x96,
    ];
    assert_eq!(
        blake2b_simd::blake2b(&proof.to_bytes()).as_array(),
        &expected_digest_2
    );
}

#[test]
fn four_row_circuit_with_zero_upper_permutation_blinders_verifies() {
    use rand_core::{CryptoRng, Error as RngError, RngCore};

    #[derive(Default)]
    struct FourRowCircuit;

    impl Circuit for FourRowCircuit {
        fn circuit(&self, _composer: &mut Composer) -> Result<(), Error> {
            Ok(())
        }
    }

    // Fixed 17-scalar blinder schedule:
    // - draws 0..11: wire blinders (nonzero)
    // - draw 11: z_poly constant blinder b_0 (nonzero)
    // - draws 12..14: z_poly linear and quadratic blinders b_1, b_2 (both zero)
    // - draws 14..17: split-quotient blinders b_12, b_13, b_14 (nonzero)
    //
    // On a 4-row circuit this gives `z_poly.degree() == 4`. Legacy `master`
    // inferred a 2-element domain from `z_poly.degree() - 2` and produced an
    // invalid proof; evaluating `L_1` on the actual proving domain fixes this
    // edge case (an intentional exception to byte compatibility with `master`).
    struct ZeroUpperPermBlinderRng {
        draw: usize,
    }

    impl RngCore for ZeroUpperPermBlinderRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!("BlsScalar::random draws via fill_bytes")
        }

        fn next_u64(&mut self) -> u64 {
            unreachable!("BlsScalar::random draws via fill_bytes")
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
            if self.draw != 12 && self.draw != 13 {
                dest[0] = (self.draw as u8).wrapping_add(1);
            }
            self.draw += 1;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ZeroUpperPermBlinderRng {}

    let mut setup_rng = StdRng::seed_from_u64(0x4a0b_0001);
    let pp = PublicParameters::setup(4, &mut setup_rng)
        .expect("public parameters should build");
    let (prover, verifier) =
        Compiler::compile::<FourRowCircuit>(&pp, b"zero-upper-perm-blinders")
            .expect("circuit should compile");
    let mut proving_rng = ZeroUpperPermBlinderRng { draw: 0 };
    let (proof, inputs) = prover
        .prove(&mut proving_rng, &FourRowCircuit)
        .expect("proof should build");
    assert_eq!(proving_rng.draw, 17);
    verifier.verify(&proof, &inputs).expect(
        "four-row proof with zero upper permutation blinders must verify",
    );
}

#[test]
fn deterministic_v3_proof_matches_master_digest() {
    #[derive(Default)]
    struct MinimalCircuit;

    impl Circuit for MinimalCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w = composer.append_witness(BlsScalar::from(7u64));
            composer.assert_equal_constant(w, BlsScalar::from(7u64), None);
            Ok(())
        }
    }

    let mut setup_rng = StdRng::seed_from_u64(0x9235_e700);
    let pp = PublicParameters::setup(1 << 10, &mut setup_rng)
        .expect("public parameters should build");
    let (prover, verifier) =
        Compiler::compile::<MinimalCircuit>(&pp, b"proof-compatibility")
            .expect("circuit should compile");
    let mut proving_rng = StdRng::seed_from_u64(0x9235_e701);
    let (proof, inputs) = prover
        .prove(&mut proving_rng, &MinimalCircuit)
        .expect("V3 proof should build");

    verifier.verify(&proof, &inputs).unwrap();

    // Pinned against `master` (`750d38d`), verified under both `std` and
    // `--no-default-features --features alloc`.
    let expected = [
        0x4f, 0xaf, 0xf9, 0xf9, 0x78, 0xfe, 0x95, 0x28, 0xab, 0xb9, 0x42, 0xd0,
        0x8d, 0x07, 0x02, 0x69, 0x6b, 0xb4, 0xa3, 0x9f, 0xfa, 0x86, 0xa9, 0x53,
        0x1f, 0xbd, 0x56, 0xcd, 0x17, 0x29, 0x7f, 0x4f, 0xaf, 0x83, 0xce, 0xf5,
        0x26, 0xe8, 0xc6, 0xfb, 0x45, 0x4f, 0x39, 0x2f, 0x9f, 0x8a, 0xda, 0x53,
        0x09, 0x62, 0x47, 0xbd, 0x36, 0x35, 0xb5, 0x19, 0x75, 0xf0, 0xf4, 0xfc,
        0x04, 0xcc, 0x83, 0x82,
    ];
    let digest = blake2b_simd::blake2b(&proof.to_bytes());
    assert_eq!(digest.as_array(), &expected);
}
