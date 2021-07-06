# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Fixed

- Fix the document references and typos [#533](https://github.com/dusk-network/plonk/pull/533)
- Fix if condition to match [#545](https://github.com/dusk-network/plonk/pull/545)

## [0.8.1] - 07-06-21

### Added

- Add `zero_var` to composer [#526](https://github.com/dusk-network/plonk/issues/526)
- Add `add_affine_to_circuit_description`to composer [#534](https://github.com/dusk-network/plonk/issues/534)

### Removed

- Remove `external_doc` and `nightly` feature [#536](https://github.com/dusk-network/plonk/issues/536)

## [0.8.0] - 03-05-21

### Added

- Add `alloc` feature to the crate [#345](https://github.com/dusk-network/plonk/issues/345)
- Add `rayon` behind `std` feature to boost proving performance [#512](https://github.com/dusk-network/plonk/issues/512)
- Add `rayon` behind `std` feature to boost verifying performance [#514](https://github.com/dusk-network/plonk/issues/514)
- Add alternative getters for `OpeningKey` & `CommitKey` in `PublicParameters` [#510](https://github.com/dusk-network/plonk/issues/510)

### Changed

- Change `constraint_system/ecc` module API improving usability and consistency [#456](https://github.com/dusk-network/plonk/issues/456)
- Change the crate to be `no_std` [#350](https://github.com/dusk-network/plonk/issues/350)
- Replace `Commitment::from_projective` for `From` trait impl  [#433] (https://github.com/dusk-network/plonk/issues/433)
- Update `canonical` from `0.5` to `0.6` [#494](https://github.com/dusk-network/plonk/issues/494)

### Removed

- Remove trimming step from `Circuit::Verify_proof` [#510](https://github.com/dusk-network/plonk/issues/510)

## [0.7.0] - 06-04-21

### Added

- Implement `VerifierData` structure. [#466](https://github.com/dusk-network/plonk/issues/466)

### Fixed

- Fix circuit debuggger compilation issues. [#488](https://github.com/dusk-network/plonk/issues/488)
- Fix import paths for lib components. [#489](https://github.com/dusk-network/plonk/issues/489)

## [0.6.1] - 12-03-21

### Changed

- Change `PublicParameters::trim` visibility to `pub`. [#460](https://github.com/dusk-network/plonk/issues/460)
- Change `StandardComposer::construct_dense_pi_vec` visibility to `pub`.[#461](https://github.com/dusk-network/plonk/issues/461)

## [0.6.0] - 11-03-21

### Added

- Implement `dusk_bytes::Serializable` for all possible structures that need serde. [#352](https://github.com/dusk-network/plonk/issues/352)
- Introduced a new type that unifies the Public Inputs `PublicInputValue`. [#416](https://github.com/dusk-network/plonk/issues/416)
- Impl `padded_circuit_size` for `VerifierKey` [#351](https://github.com/dusk-network/plonk/issues/351)
- Impl a generic method that can verify Proofs of any `Circuit`. [#396](https://github.com/dusk-network/plonk/issues/396)

### Removed

- Remove `Canon` impl for `Proof`. [#450](https://github.com/dusk-network/plonk/issues/450)
- Remove serde support completely from the repo. [#353](https://github.com/dusk-network/plonk/issues/353)
- Removed previous implementations attached to `PublicInputValues`. [#416](https://github.com/dusk-network/plonk/issues/416)
- Deprecated `anyhow` and `thiserror`. [#343](https://github.com/dusk-network/plonk/issues/343)
- Remove `serialisation` module and use single serialization fn's. [#347](https://github.com/dusk-network/plonk/issues/347)
- Remove uncessary `match` branch for `var_c` [#414](https://github.com/dusk-network/plonk/issues/414)
- Remove legacy fns and move to test modules the only-for-testing ones. [#434](https://github.com/dusk-network/plonk/issues/434)

### Changed

- Constrained as much as possible the visibility of fns, structs and it's fields [#438](https://github.com/dusk-network/plonk/issues/438)]
- Store the sparse repr of the PI and positions in a `BTreeMap` [#427](https://github.com/dusk-network/plonk/issues/427)
- Transcript Init and trim size are associated constants of the Circuit trait [#351](https://github.com/dusk-network/plonk/issues/351)
- Replace `collections::HashMap` by `hashbrown::HashMap`. [#424](https://github.com/dusk-network/plonk/issues/424)
- `Circuit` trait now only requires `padded_circuit_size` for trimming. [#351](https://github.com/dusk-network/plonk/issues/351)
- Remove `verify_proof` & `build_pi` from `Circuit`. [#396](https://github.com/dusk-network/plonk/issues/396)
- Update API naming conventions to be standard across the crate. [#354](https://github.com/dusk-network/plonk/issues/354)
- Updated the native errors to all originate from the same enum. [#343](https://github.com/dusk-network/plonk/issues/343)

## [0.5.1] - 02-02-21

### Changed

- Implement `Clone` for `PublicParameters` [#383](https://github.com/dusk-network/plonk/issues/383)

## [0.5.0] - 27-01-21

### Changed

- Upgrade canonical to v0.5 (#371)
- Upgrade dusk-bls12_381 to v0.6
- Upgrade dusk-jubjub to v0.8

## [0.4.0] - 26-01-21

### Fixed

- Heavy data structures from unchecked [#332](https://github.com/dusk-network/plonk/issues/332)

### Changed

- Refactored to/from_bytes criteria for some structs (#333)
- API breaking - Implement to/from unchecked bytes for public parameters (#332)

## [0.3.6] - 17-12-20

### Added

- To/From bytes impl for `PublicInput`.

### Changed

- Changed `compute_permutation_poly` to simpler version.

## [0.3.5] - 25-11-20

### Changed

- Changed `Proof` & `ProofEvaluations` byte conversion fn signatures.

### Added

- Implemented `Canon` for `Proof`.

## [0.3.4] - 02-11-20

### Changed

- dusk-jubjub update to `v0.5.0` with API renaming
- dusk-bls12_381 update to `v0.3.0` with API renaming

## [0.3.3] - 02-11-20

### Added

- `canon` feature to manage `Canon` derivations usage in ecc libs.

### Changed

- dusk-jubjub update to `v0.4.0`
- dusk-bls12_381 update to `v0.2.0`

## [0.3.2] - 29-10-20

### Changed

- dusk-bls12_381 update to `v0.1.5`
- dusk-jubjub update to `v0.3.10`
- Fixes #311 - big_mul and big_mul_gate documentation nit.

## [0.3.1] - 05-10-20

### Added

- Method to change the `trim_params_size` for the `Circuit` trait.

## [0.3.0] - 05-10-20

### Changed

- `Circuit` trait API & usability improvements (#313)

## [0.2.11] - 29-09-20

### Changed

- Now `Circuit` inputs are set in the circuit structure as `Option<T>`.
- Make `PublicInput::value()` fn public.
- Make pi_builder return `Result<T>`
- Refactored examples for the `Circuit` trait impl
  according to the new changes.

### Removed

- Removed `CircuitInputs` from the crate.

## [0.2.10] - 23-09-20

### Added

- Added `CircuitBuilder` trait and a example for it.

## [0.2.9] - 11-09-20

### Added

- Added `ProverKey` & `Verifierkey` to the public API as exported types.

### Changed

- Use `dusk-bls12_381 v0.1.4`.
- Use `dusk-jubjub v0.3.8`.

## [0.2.8] - 25-08-20

### Added

- Add a `variable_base_scalar_mul` method using a variable base curve add gate.

### Changed

- `ecc::scalar_mul` now named fixed_base_scalar_mul

## [0.2.7] - 13-08-20

### Added

- `Anyhow` & `thiserror` for error handling support.
- Serialisation methods for the crate public structures &
  `serde` support.
- Add a `variable_base_scalar_mul` method using a variable base curve add gate.

### Removed

- `failure` for error support since has been deprecated.

### Changed

- `add_witness_to_circuit_description` requires now just to send
  a `Scalar` and returns a constant & constrained witness `Variable`.
- Update `add_witness_to_circuit_description` fn sig (#282, #284)
- dusk-jubjub version updated to 0.3.6
- `ecc::scalar_mul` now named fixed_base_scalar_mul

## [0.2.6] - 03-08-20

### Changed

- Make public inputs vector publicly accessible.

## [0.2.5] - 31-07-20

### Changed

- ECC Point from `ecc:scalar_mul` should have its attributes exposed.

## [0.2.4] - 29-07-20

### Changed

- Changed `dusk-jubjub` version to `v0.3.5` to fix Fr random gen.

## [0.2.3] - 28-07-20

### Changed

- Changed `dusk-jubjub` version to `v0.3.4` to update dhke generation.

## [0.2.2] - 25-07-20

### Added

- Method to create constrained witness values. @CPerezz

### Changed

- Visibility of the `Proof::verify()` fn to `pub(crate)`. @CPerezz
- Changed `dusk-jubjub` version to `v0.3.3` since `v0.3.2` was yanked.

## [0.2.1] - 24-07-20 [yanked]

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
