// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

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

#[cfg(feature = "legacy-proving")]
#[test]
fn plonk_v2_and_v3_proofs_are_not_cross_compatible() {
    assert_eq!(PlonkVersion::current(), PlonkVersion::V3);

    let rng = &mut StdRng::seed_from_u64(0xC0FFEE);
    let pp = PublicParameters::setup(1 << 9, rng).expect("failed to create pp");

    let (prover, verifier) = Compiler::compile::<MulCircuit>(&pp, b"versioned")
        .expect("failed to compile circuit");

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
        .expect_err("v1 proving should be disabled");
    assert_eq!(err_v1, Error::LegacyProvingDisabled);

    let err_v2 = prover
        .prove_with_version(rng, &MulCircuit, PlonkVersion::V2)
        .expect_err("v2 proving should be disabled");
    assert_eq!(err_v2, Error::LegacyProvingDisabled);
}
