# PLONK 
![Build Status](https://github.com/dusk-network/plonk/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-plonk-blueviolet?logo=github)](https://github.com/dusk-network/plonk)
[![Documentation](https://img.shields.io/badge/docs-plonk-blue?logo=rust)](https://docs.rs/dusk-plonk/latest/dusk_plonk/)


_This is a pure Rust implementation of the PLONK proving system over BLS12-381_


This library contains a modularised implementation of KZG10 as the default
polynomial commitment scheme.

**DISCLAIMER**: This library is currently unstable and still needs to go through
an exhaustive security analysis. Use at your own risk.

## Usage

Check the 'examples' directory for the usage.

## Features

This crate includes a variety of features which will briefly be explained below:
- `alloc`: Enables the usage of an allocator and with it the capability of performing `Proof` constructions and 
  verifications. Without this feature it **IS NOT** possible to prove or verify anything. 
  Its absence only makes `dusk-plonk` export certain fixed-size data structures such as `Proof` which can be useful in no_std environments where we don't have allocators either.
- `std`: Enables `std` usage as well as `rayon` parallelization in some proving and verifying ops. 
  It also uses the `std` versions of the elliptic curve deps, which utilizes the `parallel` feature 
  from `dusk-bls12-381`. By default, this is the feature that comes enabled with the crate.
- `debug`: Enables the runtime debugger backend. Will output [CDF](https://crates.io/crates/dusk-cdf) files to the path defined in the `CDF_OUTPUT` environment variable. If used, the binary must be compiled with `debug = true`. For more info, check the [cargo book](https://doc.rust-lang.org/cargo/reference/profiles.html#debug).
  __The recommended method is to derive the std output, and the std error, and then place them in text file 
    which can be used to efficiently analyse the gates.__

## Documentation

There are two main types of documentation in this repository:

- **Crate documentation**. This provides info about all of the functions that the library provides, as well
  as the documentation regarding the data structures that it exports. To check this, please feel free to go to
  the [documentation page](https://docs.rs/dusk-plonk/) or run `make doc` or `make doc-internal`.

- **Notes**. This is a specific subset of documentation which explains the key mathematical concepts
  of PLONK and how they work with mathematical demonstrations. To check it, run `make doc` and open the resulting docs,
  which will be located under `/target` with your browser.

## Performance

Benchmarks taken on `Apple M1`, for a circuit-size of `2^16` constraints:

- Proving time: `7.871s`
- Verification time: `7.643ms` **(This time will not vary depending on the circuit-size.)**

For more results, please run `cargo bench` to get a full report of benchmarks in respect of constraint numbers.

## Acknowledgements

- Reference implementation AztecProtocol/Barretenberg
- FFT Module and KZG10 Module were taken and modified from zexe/zcash and scipr-lab, respectively.

## Licensing

This code is licensed under Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for further info.

## About

Implementation designed by the [dusk](https://dusk.network) team.

## Contributing

- If you want to contribute to this repository/project please, check [CONTRIBUTING.md](https://github.com/dusk-network/plonk/blob/master/CONTRIBUTING.md)
- If you want to report a bug or request a new feature addition, please open an issue on this repository.
