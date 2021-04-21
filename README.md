# PLONK [![Build Status](https://travis-ci.com/dusk-network/plonk.svg?branch=master)](https://travis-ci.com/dusk-network/plonk) ![GitHub issues](https://img.shields.io/github/issues-raw/dusk-network/plonk?style=plastic) ![GitHub](https://img.shields.io/github/license/dusk-network/plonk?color=%230E55EF)

_This is a pure Rust implementation of the PLONK proving system over BLS12-381_

_This code is highly experimental, use at your own risk_.

This library contains a modularised implementation of KZG10 as the default polynomial commitment scheme.

## Usage

```rust
use dusk_plonk::prelude::*
use dusk_plonk::circuit;
use dusk-bls12_381::BlsScalar;
use dusk-jubjub::{GENERATOR, JubJubScalar, JubJubAffine};

// Implement the `Circuit` trait for the circuit you want to construct.
// Implements a circuit that checks:
// 1) a + b = c where C is a PI
// 2) a <= 2^6
// 3) b <= 2^5
// 4) a * b = d where D is a PI
// 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a PI
#[derive(Debug, Default)]
pub struct TestCircuit {
    a: BlsScalar,
    b: BlsScalar,
    c: BlsScalar,
    d: BlsScalar,
    e: JubJubScalar,
    f: JubJubAffine,
}

impl Circuit for TestCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error> {
        let a = composer.add_input(self.a);
        let b = composer.add_input(self.b);
        // Make first constraint a + b = c
        composer.poly_gate(
            a,
            b,
            composer.zero_var,
            BlsScalar::zero(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            Some(-self.c),
        );
        // Check that a and b are in range
        composer.range_gate(a, 1 << 6);
        composer.range_gate(b, 1 << 5);
        // Make second constraint a * b = d
        composer.poly_gate(
            a,
            b,
            composer.zero_var,
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::one(),
            BlsScalar::zero(),
            Some(-self.d),
        );

        // This adds a PI also constraining `generator` to actually be `dusk_jubjub::GENERATOR`
        let generator = Point::from_public_affine(composer, dusk_jubjub::GENERATOR);
        let e = composer.add_input(self.e.into());
        let scalar_mul_result =
            scalar_mul::variable_base::variable_base_scalar_mul(composer, e, generator);
        // Apply the constrain
        composer.assert_equal_public_point(scalar_mul_result.into(), self.f);
        Ok(())
    }
    fn padded_circuit_size(&self) -> usize {
        1 << 11
    }

// Generate CRS (Or read it from file if already have it).
let pp_p = PublicParameters::setup(1 << 12, &mut rand::thread_rng())?;

// Initialize the circuit (with dummy inputs if you want, doesn't matter).
let mut circuit = TestCircuit::default();

// Compile the circuit. This will produce the Prover and Verifier keys as well
// as the public input positions vector.
// You can now store that to use it later on to generate proofs or verify them.
let (pk_p, vk_p, pi_pos) = circuit.compile(&pp)?;

// Prover PoV
let proof = {
    let mut circuit = TestCircuit {
        a: BlsScalar::from(20u64),
        b: BlsScalar::from(5u64),
        c: BlsScalar::from(25u64),
        d: BlsScalar::from(100u64),
        e: JubJubScalar::from(2u64),
        f: JubJubAffine::from(dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(2u64)),
    };

    circuit.gen_proof(&pp, &pk, b"Test")
}?;

// Verifier PoV

// Generate the `PublicInputValue`s vector containing your Circuit Pi's **ordered**.
let public_input_vals: Vec<PublicInputValue> = vec![
    BlsScalar::from(25u64).into(),
    BlsScalar::from(100u64).into(),
    dusk_jubjub::GENERATOR.into(),
    JubJubAffine::from(dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(2u64)).into(),
];

// Verify the proof.
assert!(circuit::verify_proof(&pp, &vk, &proof, &public_input_vals, &pi_pos, b"Test").is_ok());
```

## Documentation

There are two main types of documentation in this repository:

- **Crate documentation**. This provides info about all of the functions that the library provides as well
  as the documentation regarding the data structures that it exports. To check it, please feel free to go to
  the [documentation page](https://dusk-network.github.io/plonk/dusk_plonk/index.html)

- **Notes**. This is a specific subset of documentation which explains the mathematical key concepts
  of PLONK and how they work with mathematical demonstrations. 
  To gain access to it, you need to compile the docs locally by running: 
  `cargo doc --features nightly --lib -- --html-in-header docs/katex-header.html --open`. 
  __This requires a nightly rustc version__

## Performance

Benchmarks taken on `Intel(R) Core(TM) i5-7300HQ CPU @ 2.50GHz`
For a proof-size of `2^16` constraints/gates:

- Proving time: `5.46s`
- Verification time: `6.13ms`. **(This time will not vary depending on the circuit-size.)**

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
