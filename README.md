# PLONK 
![Build Status](https://github.com/dusk-network/plonk/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-plonk-blueviolet?logo=github)](https://github.com/dusk-network/plonk)
[![Documentation](https://img.shields.io/badge/docs-plonk-blue?logo=rust)](https://docs.rs/plonk/)


_This is a pure Rust implementation of the PLONK proving system over BLS12-381_

This library contains a modularised implementation of KZG10 as the default polynomial commitment scheme.

## Usage

```rust
use dusk-plonk::prelude::*;

// Implement a circuit that checks:
// 1) a + b = c where C is a PI
// 2) a <= 2^6
// 3) b <= 2^5
// 4) a * b = d where D is a PI
// 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a Public Input
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
    fn gadget(
        &mut self,
        composer: &mut StandardComposer,
    ) -> Result<(), Error> {
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

        let e = composer.add_input(self.e.into());
        let scalar_mul_result = composer
            .fixed_base_scalar_mul(e, dusk_jubjub::GENERATOR_EXTENDED);
        // Apply the constrain
        composer.assert_equal_public_point(scalar_mul_result, self.f);
        Ok(())
    }
    fn padded_circuit_size(&self) -> usize {
        1 << 11
    }
}

// Now let's use the Circuit we've just implemented!

let pp = PublicParameters::setup(1 << 12, &mut OsRng)?;
// Initialize the circuit
let mut circuit = TestCircuit::default();
// Compile the circuit
let (pk, vd) = circuit.compile(&pp)?;
// Prover POV
let proof = {
    let mut circuit = TestCircuit {
        a: BlsScalar::from(20u64),
        b: BlsScalar::from(5u64),
        c: BlsScalar::from(25u64),
        d: BlsScalar::from(100u64),
        e: JubJubScalar::from(2u64),
        f: JubJubAffine::from(
            dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(2u64),
        ),
    };
    circuit.gen_proof(&pp, &pk, b"Test")
}?;
// Verifier POV
let public_inputs: Vec<PublicInputValue> = vec![
    BlsScalar::from(25u64).into(),
    BlsScalar::from(100u64).into(),
    JubJubAffine::from(
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(2u64),
    )
    .into(),
];
circuit::verify_proof(
    &pp,
    &vd.key(),
    &proof,
    &public_inputs,
    &vd.pi_pos(),
    b"Test",
)
```

### Features

This crate includes a variety of features which will be shortly explained below:
- `alloc`: Enables the usage of an allocator and with it the capability of performing `Proof` constructions and 
  verifications. Without this feature **IS NOT** possible to prove or verify anything. 
  It's lack only makes `dusk-plonk` export certain fixed-size data structures such as `Proof` which can be useful in no_std envoirments where we don't have allocators either.
- `std`: Enables `std` usage as well as `rayon` parallelization in some proving and verifying ops. 
  It also uses the `std` versions of the elliptic curve deps which also pull in the `parallel` feature 
  from `dusk-bls12-381`. By default this is the feature that comes enabled with the crate.
- `nightly`: This feature is used to compile the extended docs with KateX rendering enabled. 
  See the `Documentation`section below.
- `trace`: Enables the Circuit debugger tooling. Essentially the capability of using the 
  `StandardComposer::check_circuit_satisfied` function. The function will compute each circuit gate info until 
  one of the gates does not satisfy the equation or there are no more gates. If the cause is an unsatisfied gate 
  equation, the function will panic pointing out the gate number.
- `trace-print`: Goes a step further than `trace` and prints each `gate` component data, giving a clear look to all of the 
  values that compose the circuit that we're composing. 
  __The recommended usage is to derive the std output and the std error to a text file and analyze there the gates.__
- `canon`: Enables `canonical` serialization for particular data structures which is something mostly useful to accomodate
  with the rest of Dusk's stack. Specially for storage.


## Documentation

There are two main types of documentation in this repository:

- **Crate documentation**. This provides info about all of the functions that the library provides as well
  as the documentation regarding the data structures that it exports. To check it, please feel free to go to
  the [documentation page](https://docs.rs/dusk-plonk/) or run `make doc` or `make doc-internal`.

- **Notes**. This is a specific subset of documentation which explains the mathematical key concepts
  of PLONK and how they work with mathematical demonstrations. To check it, run `make doc` and open the resulting docs
  which will be located under `/target` with your browser.

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
