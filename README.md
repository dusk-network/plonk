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
  of PLONK and how they work with mathematical demonstrations. It can be found inside of the documentation
  page in the [notes sub-section](https://dusk-network.github.io/plonk/dusk_plonk/notes/index.html)

## Performance

Benchmarks taken on `Intel(R) Xeon(R) CPU E5-1620 v4 @ 3.50GHz`.

All results are presented on a min/avg/max time based on the number of constraints performed in a circuit. None of the tests used public inputs and its number may affect the verification time.

#### Proving performance
```
2^5  = 32 constraints      time:   [31.788 ms 31.825 ms 31.862 ms]
2^6  = 64 constraints      time:   [41.388 ms 41.429 ms 41.471 ms]
2^7  = 128 constraints     time:   [63.496 ms 63.539 ms 63.573 ms]
2^8  = 256 constraints     time:   [100.32 ms 100.45 ms 100.68 ms]
2^9  = 512 constraints     time:   [140.36 ms 140.58 ms 140.78 ms]
2^10 = 1024 constraints    time:   [256.18 ms 256.48 ms 256.83 ms]
2^11 = 2048 constraints    time:   [478.55 ms 480.41 ms 482.70 ms]
2^12 = 4096 constraints    time:   [772.29 ms 776.97 ms 781.71 ms]
2^13 = 8192 constraints    time:   [1.3406 s 1.3448 s 1.3494 s]
2^14 = 16384 constraints   time:   [2.6250 s 2.6316 s 2.6379 s]
2^15 = 32768 constraints   time:   [5.1982 s 5.2228 s 5.2460 s]
2^16 = 65536 constraints   time:   [9.2356 s 9.3039 s 9.3636 s]
2^17 = 131072 constraints  time:   [17.836 s 17.883 s 17.936 s]
```

#### Verification performance
```
2^5  = 32 constraints      time:   [15.287 ms 15.700 ms 16.066 ms]
2^6  = 64 constraints      time:   [15.172 ms 15.438 ms 15.657 ms]
2^7  = 128 constraints     time:   [15.335 ms 15.666 ms 15.996 ms]
2^8  = 256 constraints     time:   [14.988 ms 15.116 ms 15.383 ms]
2^9  = 512 constraints     time:   [15.047 ms 15.181 ms 15.471 ms]
2^10 = 1024 constraints    time:   [15.630 ms 15.888 ms 16.303 ms]
2^11 = 2048 constraints    time:   [15.524 ms 15.719 ms 15.913 ms]
2^12 = 4096 constraints    time:   [15.178 ms 15.445 ms 15.593 ms]
2^13 = 8192 constraints    time:   [15.437 ms 15.874 ms 16.553 ms]
2^14 = 16384 constraints   time:   [16.059 ms 16.386 ms 16.608 ms]
2^15 = 32768 constraints   time:   [15.969 ms 16.357 ms 16.660 ms]
2^16 = 65536 constraints   time:   [16.233 ms 16.462 ms 16.639 ms]
2^17 = 131072 constraints  time:   [18.213 ms 18.680 ms 18.886 ms]
```

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
