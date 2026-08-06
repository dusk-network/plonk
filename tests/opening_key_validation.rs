// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::DeserializableSlice;
use dusk_plonk::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

const HEADER_SIZE: usize = 6 * 8;
const G1_SIZE: usize = 48;
const G2_SIZE: usize = 96;
const PROOF_COMMITMENTS: usize = 11;
const PROOF_EVALUATIONS: usize = 15;
const SCALAR_SIZE: usize = 32;

#[derive(Clone)]
struct SumCircuit {
    a: BlsScalar,
    b: BlsScalar,
    claimed: BlsScalar,
}

impl Default for SumCircuit {
    fn default() -> Self {
        Self {
            a: BlsScalar::from(2u64),
            b: BlsScalar::from(3u64),
            claimed: BlsScalar::from(5u64),
        }
    }
}

impl Circuit for SumCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let a = composer.append_public(self.a);
        let b = composer.append_public(self.b);
        let output =
            composer.gate_add(Constraint::new().left(1).right(1).a(a).b(b));
        let claimed = composer.append_public(self.claimed);
        composer.assert_equal(output, claimed);
        Ok(())
    }
}

fn read_be_u64(bytes: &[u8], offset: usize) -> usize {
    usize::try_from(u64::from_be_bytes(
        bytes[offset..offset + 8].try_into().expect("eight bytes"),
    ))
    .expect("length fits usize")
}

fn identity_g1_bytes() -> [u8; G1_SIZE] {
    let mut identity = [0u8; G1_SIZE];
    identity[0] = 0xc0;
    identity
}

fn identity_g2_bytes() -> [u8; G2_SIZE] {
    let mut identity = [0u8; G2_SIZE];
    identity[0] = 0xc0;
    identity
}

fn opening_key_offset(verifier_bytes: &[u8]) -> usize {
    let label_len = read_be_u64(verifier_bytes, 0);
    let verifier_key_len = read_be_u64(verifier_bytes, 8);
    HEADER_SIZE + label_len + verifier_key_len
}

fn replace_g(bytes: &mut [u8], opening_offset: usize) {
    bytes[opening_offset..opening_offset + G1_SIZE]
        .copy_from_slice(&identity_g1_bytes());
}

fn replace_h(bytes: &mut [u8], opening_offset: usize) {
    let h_offset = opening_offset + G1_SIZE;
    bytes[h_offset..h_offset + G2_SIZE].copy_from_slice(&identity_g2_bytes());
}

fn replace_x_h(bytes: &mut [u8], opening_offset: usize) {
    let x_h_offset = opening_offset + G1_SIZE + G2_SIZE;
    bytes[x_h_offset..x_h_offset + G2_SIZE]
        .copy_from_slice(&identity_g2_bytes());
}

fn forged_identity_proof() -> Proof {
    let mut bytes = vec![
        0u8;
        PROOF_COMMITMENTS * G1_SIZE
            + PROOF_EVALUATIONS * SCALAR_SIZE
    ];
    for commitment in
        bytes[..PROOF_COMMITMENTS * G1_SIZE].chunks_exact_mut(G1_SIZE)
    {
        commitment[0] = 0xc0;
    }
    Proof::from_slice(&bytes)
        .expect("canonical identity commitments and zero scalars decode")
}

#[test]
fn checked_artifacts_reject_degenerate_opening_keys() {
    let mut rng = StdRng::seed_from_u64(0x1d3e_1717);
    let pp = PublicParameters::setup(1 << 5, &mut rng).expect("setup");
    let (prover, verifier) =
        Compiler::compile::<SumCircuit>(&pp, b"opening-key-validation")
            .expect("compile");

    let (honest_proof, honest_inputs) = prover
        .prove(&mut rng, &SumCircuit::default())
        .expect("prove honest sum");
    verifier
        .verify(&honest_proof, &honest_inputs)
        .expect("honest parameters and proof verify");

    let forged_proof = forged_identity_proof();
    let impossible_inputs = [
        BlsScalar::from(2u64),
        BlsScalar::from(3u64),
        BlsScalar::from(9u64),
    ];
    assert!(verifier.verify(&forged_proof, &impossible_inputs).is_err());

    let verifier_bytes = verifier.to_bytes();
    let verifier_opening_offset = opening_key_offset(&verifier_bytes);
    for mutate in [replace_g, replace_h, replace_x_h] {
        let mut malformed = verifier_bytes.clone();
        mutate(&mut malformed, verifier_opening_offset);
        assert!(
            matches!(
                Verifier::try_from_bytes(malformed),
                Err(Error::BytesError(dusk_bytes::Error::InvalidData))
            ),
            "checked verifier decoding accepted a degenerate opening key"
        );
    }

    let pp_bytes = pp.to_var_bytes();
    for mutate in [replace_g, replace_h, replace_x_h] {
        let mut malformed = pp_bytes.clone();
        mutate(&mut malformed, 0);
        assert!(
            matches!(
                PublicParameters::from_slice(&malformed),
                Err(Error::BytesError(dusk_bytes::Error::InvalidData))
            ),
            "checked parameter decoding accepted a degenerate opening key"
        );
    }
}
