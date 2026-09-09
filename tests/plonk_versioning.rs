// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::DeserializableSlice;
use dusk_plonk::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[derive(Default)]
struct MulCircuit;

impl Circuit for MulCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let a = composer.append_witness(BlsScalar::from(3u64));
        let b = composer.append_witness(BlsScalar::from(4u64));
        let expected = composer.append_witness(BlsScalar::from(12u64));

        let out = composer.gate_mul(Constraint::new().mult(1).a(a).b(b));
        composer.assert_equal(out, expected);

        Ok(())
    }
}

#[test]
fn verifier_length_errors_distinguish_overflow_from_truncation() {
    let bytes = include_bytes!("fixtures/merlin-3/verifier.bin");
    assert_eq!(Verifier::try_from_bytes(bytes).unwrap().to_bytes(), bytes);
    for end in 0..bytes.len() {
        assert!(matches!(
            Verifier::try_from_bytes(&bytes[..end]),
            Err(Error::NotEnoughBytes)
        ));
    }

    // Each word fits usize on both 32- and 64-bit targets. Only the
    // byte-length multiplication or one of the three additions overflows.
    let max = usize::MAX as u64;
    for (header, overflows) in [
        ([0, 0, 0, max / 8 + 1, 0, max], true),
        ([max, 1, 0, 0, 0, 0], true),
        ([0, max, 1, 0, 0, 0], true),
        ([0, 0, max, 1, 0, 1], true),
        // At the representable boundary the missing payload is a short read.
        ([0, 0, 0, max / 8, 0, max], false),
        ([max, 0, 0, 0, 0, 0], false),
        ([0, max, 0, 0, 0, 0], false),
        ([0, 0, max - 8, 1, 0, 1], false),
    ] {
        let bytes: Vec<_> =
            header.into_iter().flat_map(u64::to_be_bytes).collect();
        let expected = if overflows {
            Error::BytesError(dusk_bytes::Error::InvalidData)
        } else {
            Error::NotEnoughBytes
        };
        assert_eq!(
            Verifier::try_from_bytes(bytes).err(),
            Some(expected),
            "header: {header:?}"
        );
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn verifier_rejects_truncated_high_bits() {
    let bytes = include_bytes!("fixtures/merlin-3/verifier.bin");
    Verifier::try_from_bytes(bytes).unwrap();
    let word = |offset| {
        u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
    };
    // Six big-endian outer words, a little-endian inner key size, and
    // a big-endian public-input index must all reject discarded high bits.
    let key_start = 48 + word(0) as usize;
    let index_start = key_start + word(8) as usize + word(16) as usize;
    for offset in [3, 11, 19, 27, 35, 43, key_start + 4, index_start + 3] {
        let mut mutated = bytes.to_vec();
        mutated[offset] |= 1;
        assert!(matches!(
            Verifier::try_from_bytes(mutated),
            Err(Error::BytesError(dusk_bytes::Error::InvalidData))
        ));
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn prover_rejects_truncated_commit_key_length_high_bits() {
    let mut rng = StdRng::seed_from_u64(63);
    let pp = PublicParameters::setup(1 << 5, &mut rng).unwrap();
    let (prover, _) = Compiler::compile::<MulCircuit>(&pp, b"length").unwrap();
    let mut bytes = prover.to_bytes();
    assert_eq!(Prover::try_from_bytes(&bytes).unwrap().to_bytes(), bytes);
    let word = |offset| {
        u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
            as usize
    };
    let commit_start = 56 + word(8) + word(16);
    bytes[commit_start + 4] |= 1;
    assert!(matches!(
        Prover::try_from_bytes(bytes),
        Err(Error::BytesError(dusk_bytes::Error::InvalidData))
    ));
}

#[test]
fn upstream_merlin_3_proofs_remain_valid() {
    let verifier = Verifier::try_from_bytes(include_bytes!(
        "fixtures/merlin-3/verifier.bin"
    ))
    .expect("upstream verifier must deserialize");

    for (version, bytes) in [
        (
            PlonkVersion::V2,
            include_bytes!("fixtures/merlin-3/v2.proof"),
        ),
        (
            PlonkVersion::V3,
            include_bytes!("fixtures/merlin-3/v3.proof"),
        ),
    ] {
        let proof =
            Proof::from_slice(bytes).expect("upstream proof must decode");
        verifier
            .verify_with_version(&proof, &[BlsScalar::from(12u64)], version)
            .expect("upstream proof must verify with the matching version");
        assert!(
            verifier
                .verify_with_version(&proof, &[BlsScalar::from(13u64)], version)
                .is_err(),
            "altered public input must be rejected"
        );
    }
}

#[cfg(feature = "legacy-proving")]
#[test]
fn plonk_v2_and_v3_proofs_are_not_cross_compatible() {
    assert_eq!(PlonkVersion::current(), PlonkVersion::V3);

    let rng = &mut StdRng::seed_from_u64(0xC0FFEE);
    let pp = PublicParameters::setup(1 << 9, rng).expect("failed to create pp");

    let (prover, verifier) = Compiler::compile::<MulCircuit>(&pp, b"versioned")
        .expect("failed to compile circuit");

    let err_v1 = prover
        .prove_with_version(rng, &MulCircuit, PlonkVersion::V1)
        .expect_err("v1 proving should be unsupported");
    assert_eq!(err_v1, Error::UnsupportedProvingVersion);

    let (proof_v2, pi_v2) = prover
        .prove_with_version(rng, &MulCircuit, PlonkVersion::V2)
        .expect("v2 proving failed");

    verifier
        .verify_with_version(&proof_v2, &pi_v2, PlonkVersion::V2)
        .expect("v2 proof must verify under v2");
    assert!(
        verifier
            .verify_with_version(&proof_v2, &pi_v2, PlonkVersion::V3)
            .is_err(),
        "v2 proof must not verify under v3"
    );

    let (proof_v3, pi_v3) = prover
        .prove_with_version(rng, &MulCircuit, PlonkVersion::V3)
        .expect("v3 proving failed");

    verifier
        .verify_with_version(&proof_v3, &pi_v3, PlonkVersion::V3)
        .expect("v3 proof must verify under v3");
    assert!(
        verifier
            .verify_with_version(&proof_v3, &pi_v3, PlonkVersion::V2)
            .is_err(),
        "v3 proof must not verify under v2"
    );
}

#[cfg(not(feature = "legacy-proving"))]
#[test]
fn legacy_proving_is_disabled_without_feature() {
    assert_eq!(PlonkVersion::current(), PlonkVersion::V3);

    let rng = &mut StdRng::seed_from_u64(0xC0FFEE);
    let pp = PublicParameters::setup(1 << 9, rng).expect("failed to create pp");
    let (prover, _) = Compiler::compile::<MulCircuit>(&pp, b"versioned")
        .expect("failed to compile circuit");

    let err_v1 = prover
        .prove_with_version(rng, &MulCircuit, PlonkVersion::V1)
        .expect_err("v1 proving should be unsupported");
    assert_eq!(err_v1, Error::UnsupportedProvingVersion);

    let err_v2 = prover
        .prove_with_version(rng, &MulCircuit, PlonkVersion::V2)
        .expect_err("v2 proving should be disabled");
    assert_eq!(err_v2, Error::LegacyProvingDisabled);
}
