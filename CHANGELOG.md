# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [Unreleased]


## [0.2.1] - 24-07-20

### Added
- Method to create constrained witness values. @CPerezz

### Changed
- Visibility of the `Proof::verify()` fn to `pub(crate)`. @CPerezz
 

## [0.2.0] - 20-07-20

### Added
- Prover and Verifier abstraction @kevaundray
- Error handling and custom errors @CPerezz
- Add prelude file @CPerezz
- Add identity separation challenge to each identity. @kevaundray
- Decouple Prover and Verifier Key @kevaundray
- Remove Preprocessed circuit @kevaundray
- Implement ECC gate @kevaundray
- Add math-related docs @Bounce23
- Add identity separation challenge to each identity @kevaundray

### Changed
- Widget splitting to modularize the codebase @kevaundray

### Fixed
- Bug in "front-end" assertions in logic_constraint gates @CPerezz
- Broken links in the docs @CPerezz

### Removed
- Serde support for the time being. 


## [0.1.0] - 25-04-20

### Added

- PLONK algorithm implementation.
- Example folders.
- Doc notes with kateX.
- KZG10 polynomial commitment scheme implementation.
- fft module with Polynomial ops implemented.
- Proof system module.

### Changed

### Fixed

### Removed
