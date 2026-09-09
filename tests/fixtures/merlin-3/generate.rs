// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Fixture generation and cross-build checks; see README.md.
//! Deterministic RNG seeds are test-only, never production setup.
use std::path::PathBuf;
use std::{env, fs};

use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_plonk::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[derive(Default)]
struct Product(BlsScalar);

impl Circuit for Product {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let a = composer.append_witness(BlsScalar::from(3));
        let b = composer.append_witness(BlsScalar::from(4));
        let result = composer.gate_mul(Constraint::new().mult(1).a(a).b(b));
        let public = composer.append_public(self.0);
        composer.assert_equal(result, public);
        Ok(())
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(args.len(), 3, "usage: merlin_compat write|verify DIRECTORY");
    let directory = PathBuf::from(&args[2]);
    let versions = [("v2", PlonkVersion::V2), ("v3", PlonkVersion::V3)];
    if args[1] == "write" {
        fs::create_dir_all(&directory).unwrap();
        let mut rng = StdRng::seed_from_u64(0x4d45_524c_494e);
        let pp = PublicParameters::setup(1 << 8, &mut rng).unwrap();
        let (prover, verifier) = Compiler::compile::<Product>(
            &pp,
            b"dusk-merlin release compatibility",
        )
        .unwrap();
        fs::write(directory.join("verifier.bin"), verifier.to_bytes()).unwrap();
        for (name, version) in versions {
            let (proof, inputs) = prover
                .prove_with_version(
                    &mut rng,
                    &Product(BlsScalar::from(12)),
                    version,
                )
                .unwrap();
            verifier
                .verify_with_version(&proof, &inputs, version)
                .unwrap();
            fs::write(
                directory.join(format!("{name}.proof")),
                proof.to_bytes(),
            )
            .unwrap();
            let bytes: Vec<u8> =
                inputs.iter().flat_map(|input| input.to_bytes()).collect();
            fs::write(directory.join(format!("{name}.inputs")), bytes).unwrap();
        }
    } else {
        assert_eq!(args[1], "verify");
        let verifier = Verifier::try_from_bytes(
            fs::read(directory.join("verifier.bin")).unwrap(),
        )
        .unwrap();
        for (name, version) in versions {
            let proof = Proof::from_slice(
                &fs::read(directory.join(format!("{name}.proof"))).unwrap(),
            )
            .unwrap();
            let bytes =
                fs::read(directory.join(format!("{name}.inputs"))).unwrap();
            let (inputs, remainder) = bytes.as_chunks::<32>();
            assert!(!inputs.is_empty() && remainder.is_empty());
            let mut inputs: Vec<_> = inputs
                .iter()
                .map(|bytes| BlsScalar::from_slice(bytes).unwrap())
                .collect();
            verifier
                .verify_with_version(&proof, &inputs, version)
                .unwrap();
            inputs[0] += BlsScalar::one();
            assert!(
                verifier
                    .verify_with_version(&proof, &inputs, version)
                    .is_err()
            );
            println!(
                "{name}: stored proof accepted; altered public input rejected"
            );
        }
    }
}
