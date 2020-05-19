# PLONK [![Build Status](https://travis-ci.com/dusk-network/plonk.svg?branch=master)](https://travis-ci.com/dusk-network/plonk) ![GitHub issues](https://img.shields.io/github/issues-raw/dusk-network/plonk?style=plastic) ![GitHub](https://img.shields.io/github/license/dusk-network/plonk?color=%230E55EF) 



*This is a pure Rust implementation of the PLONK proving system over BLS12-381*

_This code is highly experimental, use at your own risk_.

This library contains a modularised implementation of KZG10 as the default polynomial commitment scheme.


## Documentation

There are two main types of documentation in this repository:
- **Crate documentation**. This provides info about all of the functions that the library provides as well
as the documentation regarding the data structures that it exports. To check it, please feel free to go to
the [documentation page](https://dusk-network.github.io/plonk/dusk_plonk/index.html)

- **Notes**. This is a specific subset of documentation which explains the mathematical key concepts
of PLONK and how they work with mathematical demonstrations. It can be found inside of the documentation
page in the [notes sub-section](https://dusk-network.github.io/plonk/dusk_plonk/notes/index.html)

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