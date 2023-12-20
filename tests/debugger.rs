// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::{env, io};

use dusk_cdf::CircuitDescription;
use dusk_plonk::prelude::*;

#[derive(Debug, Default)]
struct EmptyCircuit;

impl Circuit for EmptyCircuit {
    fn circuit(&self, _composer: &mut Composer) -> Result<(), Error> {
        Ok(())
    }
}

#[test]
fn generate_cdf_works() -> io::Result<()> {
    let rng = &mut rand::thread_rng();

    let dir = tempdir::TempDir::new("plonk-cdf")?;
    let path = dir.path().canonicalize()?.join("test.cdf");

    let label = b"transcript-arguments";
    let pp = PublicParameters::setup(1 << 5, rng)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let (prover, _verifier) = Compiler::compile::<EmptyCircuit>(&pp, label)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    env::set_var("CDF_OUTPUT", &path);

    prover
        .prove(rng, &EmptyCircuit)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    path.canonicalize().and_then(CircuitDescription::open)?;

    Ok(())
}
