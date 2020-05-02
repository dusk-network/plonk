# PLONK [![Build Status](https://travis-ci.com/dusk-network/plonk.svg?branch=master)](https://travis-ci.com/dusk-network/plonk) ![GitHub issues](https://img.shields.io/github/issues-raw/dusk-network/plonk?style=plastic) ![GitHub](https://img.shields.io/github/license/dusk-network/plonk?color=%230E55EF) 



*This is a pure Rust implementation of the PLONK proving system over BLS12-381*

_This code is highly experimental, use at your own risk_.

This library contains a modularised implementation of KZG10 as the default polynomial commitment scheme.

## Example

The following example shows how to setup the SRS and verify whether a value is a boolean
```rust
//! To understand the following code and the reasons why everything is done
//! we strongly recommend the user to check the examples folder.
extern crate bincode;
#[macro_use]
extern crate lazy_static;
extern crate dusk_plonk;
extern crate merlin;

use dusk_bls12_381::Scalar;
use dusk_plonk::commitment_scheme::kzg10::{CommitKey, OpeningKey, PublicParameters};
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::proof_system::{PreProcessedCircuit, Proof, Prover};
use failure::Error;
use merlin::Transcript;
use std::fs;

// Load the constants that are already known before the program runs.
lazy_static! {
    static ref PREPROCESSED_CIRCUIT: PreProcessedCircuit = {
        let ser_data = fs::read("examples/.prep_circ_2_3.bin")
            .expect("Missing PreProcessedCircuit serialized data.");
        let prep_circ: PreProcessedCircuit = bincode::deserialize(&ser_data).unwrap();
        prep_circ
    };
    static ref OPENING_KEY: OpeningKey = {
        let ser_pub_params = fs::read(&"examples/.public_params.bin")
            .expect("File not found. Run example `0_setup_srs.rs` first please");
        let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();
        let opening_key: OpeningKey = pub_params.trim(CIRCUIT_SIZE.next_power_of_two()).unwrap().1;
        opening_key
    };
    static ref COMMIT_KEY: CommitKey = {
        let ser_pub_params = fs::read(&"examples/.public_params.bin")
            .expect("File not found. Run example `0_setup_srs.rs` first please");
        let pub_params: PublicParameters = bincode::deserialize(&ser_pub_params).unwrap();
        let commit_key: CommitKey = pub_params
            .trim(2 * CIRCUIT_SIZE.next_power_of_two())
            .unwrap()
            .0;
        commit_key
    };
}
// Define constants we already know.
const CIRCUIT_SIZE: usize = 20usize;

// This function will print the circuit logic that we define on it into our Composer.
fn gadget_builder(composer: &mut StandardComposer, inputs: &[Scalar], final_result: Scalar) {
    let a = composer.add_input(inputs[0]);
    let b = composer.add_input(inputs[1]);
    let c = composer.add_input(inputs[2]);
    let d = composer.add_input(inputs[3]);

    let a_plus_b = composer.add(
        (Scalar::one(), a),
        (Scalar::one(), b),
        Scalar::zero(),
        Scalar::zero(),
    );

    let c_plus_d = composer.big_add(
        (Scalar::one(), c),
        (Scalar::one(), d),
        (Scalar::zero(), composer.zero_var),
        Scalar::zero(),
        Scalar::zero(),
    );

    let ab_xor_cd = composer.logic_xor_gate(a_plus_b, c_plus_d, 14usize);
    composer.bool_gate(ab_xor_cd);
    composer.constrain_to_constant(ab_xor_cd, Scalar::zero(), final_result);
    composer.add_dummy_constraints();
}

fn elaborate_proof(prover: &mut Prover) -> Result<Proof, Error> {
    prover.prove_with_preprocessed(&COMMIT_KEY, &PREPROCESSED_CIRCUIT)
}

fn verify_proof(proof: &Proof, pub_input: Scalar) -> Result<(), Error> {
    let mut verif_transcript = Transcript::new(b"Gadget-Orientation-Is-Cool");
    let zero = Scalar::zero();

    proof.verify(
        &PREPROCESSED_CIRCUIT,
        &mut verif_transcript,
        &OPENING_KEY,
        &[
            zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, pub_input,
        ],
    )
}

fn start_proving(inputs: &[Scalar], final_result: Scalar) -> Result<Proof, Error> {
    let mut prover = Prover::new(b"Gadget-Orientation-Is-Cool");
    gadget_builder(prover.mut_cs(), inputs, final_result);
    elaborate_proof(&mut prover)
}

fn main() -> Result<(), Error> {
    // The public input is PUBLIC so we assume that the `Provers` and `Verifiers`
    // already know it.
    let pub_input = -Scalar::one();

    // Let's suppose that the following inputs arrive through the network or another rust
    // process or function:
    let inputs = vec![
        Scalar::from(6u64),
        Scalar::from(4u64),
        Scalar::from(3u64),
        Scalar::from(8u64),
    ];
    // We just need to do call one function to build a proof
    let proof = start_proving(&inputs, pub_input)?;

    // Verification
    verify_proof(&proof, pub_input)?;
    println!("Proof constructed in the example was succesfully verified!");

    //
    //
    // We can also asume that we just recieve `Proof`s on a serialized manner that have been
    // sent through the network.
    let ok_proof_data =
        fs::read("examples/.proof_ok_2_3.bin").expect("Missing Proof file \".proof_ok_2_3.bin\"");
    let ok_proof: Proof = bincode::deserialize(&ok_proof_data).unwrap();

    let ko_proof_data =
        fs::read("examples/.proof_ko_2_3.bin").expect("Missing Proof file \".proof_ko_2_3.bin\"");
    let ko_proof: Proof = bincode::deserialize(&ko_proof_data).unwrap();

    verify_proof(&ok_proof, pub_input)?;
    println!("OK Proof constructed before was succesfully verified!");
    match verify_proof(&ko_proof, pub_input) {
        Ok(()) => panic!("Incorrect proof has been verified successfully!"),
        Err(e) => {
            println!(
            "KO Proof constructed before was succesfully verified unsuccessfully as we expected! with the following error: {:?}", e);
            Ok(())
        }
    }
}

```

## Documentation

There are two main types of documentation in this repository:
- **Crate documentation**. This provides info about all of the functions that the library provides as well
as the documentation regarding the data structures that it exports. To check it, please feel free to go to
the [documentation page](https://dusk-network.github.io/plonk/dusk_plonk/index.html)

- **Notes**. This is a specific subset of documentation which explains the matematical key concepts
of PLONK and how they work with mathematical demonstrations. It can be found inside of the documentation
page in the [notes sub-section](https://dusk-network.github.io/plonk/dusk_plonk/notes/index.html)

- **Examples**. This provides the resources and explanations needed to understand how the library works.
Includes file examples on how to use `dusk-plonk` as a dependency on your projects.
To check this please go to the [examples folder](https://github.com/dusk-network/plonk/tree/master/examples).

## Performance

Benchmarks taken on `Intel(R) Core(TM) i5-7300HQ CPU @ 2.50GHz`
For a proof-size of `2^16` constraints/gates:
- Proving time: `5.46s`
- Verification time: `6.13ms`. **(This time will not vary depending on the proof-size.)**

## Acknowledgements

- Reference implementation AztecProtocol/Barretenberg
- FFT Module and KZG10 Module were taken and modified from zexe/zcash and scipr-lab respectively.

## Licensing

This code is licensed under Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for further info.

## About

Implementation designed by the [dusk](https://dusk.network) team.

## Contributing
- If you want to contribute to this repository/project please, check [CONTRIBUTING.md](https://github.com/dusk-network/plonk/blob/master/CONTRIBUTING.md)
- If you want to report a bug or request a new feature addition, please open an issue on this repository.