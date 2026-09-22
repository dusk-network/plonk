// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::Prover;
use crate::error::Error;
use crate::fft::EvaluationDomain;
use crate::prelude::{
    Circuit, Compiler, Composer, Constraint, PlonkVersion, Proof,
    PublicParameters, Verifier,
};

#[test]
fn wire_blinding_preserves_rows_and_required_degrees() {
    let mut rng = StdRng::seed_from_u64(39231);
    for size in [4, 16] {
        let domain = EvaluationDomain::new(size).unwrap();
        let witnesses: Vec<_> =
            (0..size).map(|i| BlsScalar::from(i as u64 + 5)).collect();
        let blinders = Prover::sample_wire_blinders(&mut rng);
        let polynomials =
            Prover::blind_wire_polynomials([&witnesses; 4], &blinders, &domain);
        for (polynomial, hiding_degree) in polynomials.iter().zip([2, 2, 1, 2])
        {
            assert_eq!(polynomial.degree(), size + hiding_degree);
            for (row, witness) in domain.elements().zip(&witnesses) {
                assert_eq!(polynomial.evaluate(&row), *witness);
            }
        }
    }
}

#[derive(Default)]
struct PaddedCircuit {
    extra_rows: usize,
}

impl Circuit for PaddedCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        for _ in 0..self.extra_rows {
            composer.assert_equal(Composer::ONE, Composer::ONE);
        }
        Ok(())
    }
}

#[test]
fn blinded_proofs_respect_exact_key_capacity_after_serialization() {
    let mut rng = StdRng::seed_from_u64(0xb11d);
    let versions = [
        PlonkVersion::V3,
        #[cfg(feature = "legacy-proving")]
        PlonkVersion::V2,
    ];

    // Include the minimum domain n = 4, padded circuits, and exact fills.
    // At n = 4 the honest degree bound 4n + 9 is closest to the quotient
    // rejection threshold 7n; a satisfied circuit must still be accepted.
    for (extra_rows, size) in [
        (0, 4),
        (1, 8),
        (4, 8),
        (5, 16),
        (12, 16),
        (16, 32),
        (28, 32),
    ] {
        let pp = PublicParameters::setup(size, &mut rng).unwrap();
        let pp = PublicParameters::from_slice(&pp.to_var_bytes()).unwrap();
        assert_eq!(pp.max_degree(), size + 9);
        let circuit = PaddedCircuit { extra_rows };
        let (prover, verifier) =
            Compiler::compile_with_circuit(&pp, b"blinding-capacity", &circuit)
                .unwrap();
        assert_eq!(prover.size, size);

        // Setup and compilation must agree on the actual n + 9 boundary,
        // including after decoding, without requiring a larger setup.
        let prover = Prover::try_from_bytes(prover.to_bytes()).unwrap();
        let verifier = Verifier::try_from_bytes(verifier.to_bytes()).unwrap();
        assert_eq!(prover.commit_key.max_degree(), size + 9);

        // The verifier produced with the former n + 6 capacity is unchanged
        // and accepts proofs with the corrected blinding after decoding.
        let composer = Composer::prove(prover.constraints, &circuit).unwrap();
        let (_, old_verifier) = Compiler::preprocess(
            b"blinding-capacity",
            pp.commit_key.truncate(size + 6).unwrap(),
            pp.opening_key.clone(),
            &composer,
        )
        .unwrap();
        assert_eq!(old_verifier.to_bytes(), verifier.to_bytes());
        let old_verifier =
            Verifier::try_from_bytes(old_verifier.to_bytes()).unwrap();

        for version in versions {
            let (proof, inputs) = prover
                .prove_with_version(&mut rng, &circuit, version)
                .unwrap();
            let proof = Proof::from_slice(&proof.to_bytes()).unwrap();
            verifier
                .verify_with_version(&proof, &inputs, version)
                .unwrap();
            old_verifier
                .verify_with_version(&proof, &inputs, version)
                .unwrap();

            // Decoding a key does not establish sufficient capacity.
            // Undersized keys must fail when used for proving.
            for allowance in [6, 8] {
                let mut short_prover = prover.clone();
                short_prover.commit_key =
                    pp.commit_key.truncate(size + allowance).unwrap();
                let short_prover =
                    Prover::try_from_bytes(short_prover.to_bytes()).unwrap();
                assert!(matches!(
                    short_prover
                        .prove_with_version(&mut rng, &circuit, version),
                    Err(Error::PolynomialDegreeTooLarge)
                ));
            }
        }
    }
}

#[test]
fn sufficiently_large_legacy_setup_and_prover_key_remain_usable() {
    let mut rng = StdRng::seed_from_u64(0x1e6ac7);
    let mut pp = PublicParameters::setup(32, &mut rng).unwrap();
    // Use a setup whose capacity exceeds this circuit's requirements.
    pp.commit_key = pp.commit_key.truncate(32 + 6).unwrap();
    let pp = PublicParameters::from_slice(&pp.to_var_bytes()).unwrap();
    let circuit = PaddedCircuit { extra_rows: 12 };
    let label = b"legacy-blinding-capacity";
    let (prover, verifier) =
        Compiler::compile_with_circuit(&pp, label, &circuit).unwrap();
    assert_eq!(prover.size, 16);
    assert_eq!(prover.commit_key.max_degree(), 16 + 9);

    // A serialized prover with extra capacity must remain usable.
    let composer = Composer::prove(prover.constraints, &circuit).unwrap();
    let (old_prover, old_verifier) = Compiler::preprocess(
        label,
        pp.commit_key.clone(),
        pp.opening_key.clone(),
        &composer,
    )
    .unwrap();
    let old_prover = Prover::try_from_bytes(old_prover.to_bytes()).unwrap();
    assert_eq!(old_verifier.to_bytes(), verifier.to_bytes());
    let versions = [
        PlonkVersion::V3,
        #[cfg(feature = "legacy-proving")]
        PlonkVersion::V2,
    ];
    for version in versions {
        for prover in [&prover, &old_prover] {
            let (proof, inputs) = prover
                .prove_with_version(&mut rng, &circuit, version)
                .unwrap();
            old_verifier
                .verify_with_version(&proof, &inputs, version)
                .unwrap();
        }
    }
}

#[derive(Default)]
struct PublicSumCircuit {
    left: BlsScalar,
    right: BlsScalar,
    sum: BlsScalar,
}

impl Circuit for PublicSumCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let left = composer.append_witness(self.left);
        let right = composer.append_witness(self.right);
        let sum = composer.append_witness(self.sum);
        composer.append_gate(
            Constraint::new()
                .left(1)
                .right(1)
                .output(-BlsScalar::one())
                .a(left)
                .b(right)
                .c(sum),
        );
        composer.assert_equal_constant(sum, BlsScalar::zero(), Some(self.sum));
        Ok(())
    }
}

#[test]
fn fresh_blinding_preserves_statement_and_rejects_invalid_assignments() {
    let mut rng = StdRng::seed_from_u64(0xf2e5);
    let pp = PublicParameters::setup(32, &mut rng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<PublicSumCircuit>(&pp, b"fresh-blinding").unwrap();
    assert_eq!(prover.size, 8);
    let versions = [
        PlonkVersion::V3,
        #[cfg(feature = "legacy-proving")]
        PlonkVersion::V2,
    ];

    for version in versions {
        for sum in [BlsScalar::zero(), BlsScalar::from(17)] {
            let circuit = PublicSumCircuit {
                left: BlsScalar::from(7),
                right: sum - BlsScalar::from(7),
                sum,
            };
            let (first, inputs) = prover
                .prove_with_version(&mut rng, &circuit, version)
                .unwrap();
            let (second, repeated_inputs) = prover
                .prove_with_version(&mut rng, &circuit, version)
                .unwrap();
            assert_eq!(inputs, vec![sum]);
            assert_eq!(inputs, repeated_inputs);
            verifier
                .verify_with_version(&first, &inputs, version)
                .unwrap();
            verifier
                .verify_with_version(&second, &inputs, version)
                .unwrap();

            // Fresh masks must affect every witness-bearing commitment,
            // including the once-opened c wire and the permutation product.
            for (first, second) in [
                (first.a_comm, second.a_comm),
                (first.b_comm, second.b_comm),
                (first.c_comm, second.c_comm),
                (first.d_comm, second.d_comm),
                (first.z_comm, second.z_comm),
                (first.t_low_comm, second.t_low_comm),
                (first.t_mid_comm, second.t_mid_comm),
                (first.t_high_comm, second.t_high_comm),
                (first.t_fourth_comm, second.t_fourth_comm),
            ] {
                assert_ne!(first, second);
            }

            let wrong_inputs = [sum + BlsScalar::one()];
            assert!(
                verifier
                    .verify_with_version(&first, &wrong_inputs, version)
                    .is_err()
            );

            let invalid = PublicSumCircuit {
                left: circuit.left + BlsScalar::one(),
                ..circuit
            };
            // Also exercise the degree-based satisfaction check with a key
            // large enough to commit to an invalid quotient's chunks.
            for oversized in [false, true] {
                let mut prover = prover.clone();
                if oversized {
                    prover.commit_key = pp.commit_key.clone();
                }
                assert!(matches!(
                    prover.prove_with_version(&mut rng, &invalid, version),
                    Err(Error::CircuitUnsatisfied)
                ));
            }
        }
    }
}
