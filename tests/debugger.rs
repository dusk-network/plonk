use std::{env, io};

use dusk_cdf::CircuitDescription;
use dusk_plonk::prelude::*;

#[derive(Debug, Default)]
struct EmptyCircuit;

impl Circuit for EmptyCircuit {
    fn circuit<C>(&self, _composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
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
