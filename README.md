# PLONK 
![Build Status](https://github.com/dusk-network/plonk/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-plonk-blueviolet?logo=github)](https://github.com/dusk-network/plonk)
[![Documentation](https://img.shields.io/badge/docs-plonk-blue?logo=rust)](https://docs.rs/dusk-plonk/latest/)

_This is a pure Rust implementation of the PLONK proving system over BLS12-381._

This library contains a modular implementation of KZG10 as the default polynomial commitment scheme. Moreover, it includes custom gates for efficiency purposes. The details on our specific implementation can be found [here](docs/dusk-plonk-specs.pdf).

**DISCLAIMER**: This library is currently unstable and still needs to undergo an exhaustive security analysis. Use at your own risk.

## Usage

To see how to use this library, check the 'examples' directory.

## Features

This crate includes a variety of features which are briefly explained below:
- `alloc`: Enables the usage of an allocator, allowing for `Proof` constructions and verifications. Without this feature it **IS NOT** possible to prove or verify anything. 
  Its absence only makes `dusk-plonk` export certain fixed-size data structures such as `Proof`, which can be useful in no_std environments where we don't have allocators available.
- `std`: Enables `std` usage as well as `rayon` parallelization in some proving and verifying operations. 
  It also uses the `std` versions of the elliptic curve dependencies, utilizing the `parallel` feature 
  from `dusk-bls12-381`. This feature is enabled by default.
- `debug`: Enables the runtime debugger backend, outputting [CDF](https://crates.io/crates/dusk-cdf) files to the path defined in the `CDF_OUTPUT` environment variable. When used, the binary must be compiled with `debug = true`. For more info, check the [cargo book](https://doc.rust-lang.org/cargo/reference/profiles.html#debug).
  __It is recommended to derive the std output and std error and then place them in a text file for efficient gate analysis.__

## Documentation

The crate documentation provides information about all the functions that the library provides, as well
as the documentation regarding the data structures that it exports. To check this, visit the [documentation page](https://docs.rs/dusk-plonk/) or run `make doc` or `make doc-internal`.

## Performance

Benchmarks taken on `Apple M1`, for a circuit-size of `2^16` constraints:

- Proving time: `7.871s`
- Verification time: `2.821ms` **(This time does not vary depending on the circuit-size.)**

For more results, please run `cargo bench` to get a full report of benchmarks in respect of constraint numbers.

## Acknowledgements

- Reference implementation by Aztec Protocol/Barretenberg.
- FFT Module and KZG10 Module were adapted from ZEXE/Zcash and SCIPR Lab, respectively.

## Licensing

This code is licensed under the Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for more information.

## About

This implementation is designed by the [Dusk](https://dusk.network) team.

## Contributing

- If you want to contribute to this repository/project, please check our [CONTRIBUTING.md](https://github.com/dusk-network/plonk/blob/master/CONTRIBUTING.md).
- If you want to report a bug or request a new feature addition, please open an issue on this repository.
