# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Add the blinding factors to provide Zero-Knowledge [#650](https://github.com/dusk-network/plonk/issues/650)

### Changed

- Change variable names for more consistency with the paper [#631](https://github.com/dusk-network/plonk/issues/631)
- Change `append_constant` to accept generic input [#672](https://github.com/dusk-network/plonk/issues/672)

### Removed

- Remove `hash_tables` module [#663](https://github.com/dusk-network/plonk/pull/663)

### Fixed

- Fix `logic_gate` for `bit_num` = 256 [#678](https://github.com/dusk-network/plonk/pull/678)

## [0.10.0] - 24-02-22

## Changed

- Update canonical and canonical-derive to 0.7 [#666](https://github.com/dusk-network/plonk/pull/666)
- Update dusk-bls12_381 to 0.9 [#666](https://github.com/dusk-network/plonk/pull/666)
- Update jubjub to 0.11 [#666](https://github.com/dusk-network/plonk/pull/666)
- Update rust edition to 2021 [#667](https://github.com/dusk-network/plonk/pull/667)

## [0.9.2] - 06-01-22

### Added

- Add `circuit::verify` to `Circuit` module. [#656](https://github.com/dusk-network/plonk/pull/656)

## [0.9.1] - 05-01-22

### Added

- Add support for rendering LaTeX in the docs [#630](https://github.com/dusk-network/plonk/pull/630)
- Add `append_public_witness` to `TurboComposer`. [#654](https://github.com/dusk-network/plonk/issues/654)

## [0.9.0] - 10-11-21

### Added

- Add back benchmarks to the crate. [#555](https://github.com/dusk-network/plonk/issues/555)
- Add `ProverKey::num_multiset` [#581](https://github.com/dusk-network/plonk/issues/581)
- Add alloc feature for lookup Vec structs [#582](https://github.com/dusk-network/plonk/issues/582)
- Add test coverage for polynomial evaluations [#586](https://github.com/dusk-network/plonk/issues/586)
- Add `Witness` by removing `AllocatedScalar`. [#588](https://github.com/dusk-network/plonk/issues/588)
- Add missing dummy constraints in test [#592](https://github.com/dusk-network/plonk/issues/592)
- Add codeconv config [#594](https://github.com/dusk-network/plonk/issues/594)
- Add `Constraint` for circuit description. [#608](https://github.com/dusk-network/plonk/issues/608)
- Add public unsafe `evaluate_witness()` to the composer [#612](https://github.com/dusk-network/plonk/issues/612)

### Changed

- Change `StandardComposer` to `TurboComposer`. [#288](https://github.com/dusk-network/plonk/issues/288)
- Change to use `From<JubJubScalar>` for BlsScalar [#294](https://github.com/dusk-network/plonk/issues/294)
- Change unit tests as integration tests when possible [#500](https://github.com/dusk-network/plonk/issues/500)
- Change to arrays some tuples in permutation module [#562](https://github.com/dusk-network/plonk/issues/562)
- Change `poly_gate` to init lookup wire with zero [#578](https://github.com/dusk-network/plonk/issues/578)
- Change `TurboComposer` to consistent API. [#587](https://github.com/dusk-network/plonk/issues/587)
- Change `plonkup_gate` to use public inputs. [#584](https://github.com/dusk-network/plonk/issues/584)
- Change coverage to use less compile flags. [#605](https://github.com/dusk-network/plonk/issues/605)
- Change `Constraint` to accept witness args. [#624](https://github.com/dusk-network/plonk/issues/624)

### Fixed

- Fix the document references and typos [#533](https://github.com/dusk-network/plonk/pull/533)
- Fix if condition to match [#545](https://github.com/dusk-network/plonk/pull/545)
- Fix `Prover::preprocess` circuit size for plookup [#580](https://github.com/dusk-network/plonk/pull/580)
- Fix ignored tests by reincluding them [#593](https://github.com/dusk-network/plonk/issues/593)
- Fix benches and make CI fail if they don't compile [#610](https://github.com/dusk-network/plonk/issues/610)
- Fix several small nits and unnecessary operations [#611](https://github.com/dusk-network/plonk/issues/611)
- Fix clippy reports [#622](https://github.com/dusk-network/plonk/pull/622)

### Removed

- Remove old perm-computation fns from perm module [#515](https://github.com/dusk-network/plonk/issues/515)
- Remove unused `plonkup` module. [#583](https://github.com/dusk-network/plonk/issues/583)
- Remove the re-export of jubjub and bls libs [#558](https://github.com/dusk-network/plonk/issues/558)
- Remove `Plonkup3Arity` [#589](https://github.com/dusk-network/plonk/issues/589)
- Remove windows from CI. [#616](https://github.com/dusk-network/plonk/issues/616)

## [0.8.2] - 17-09-21

### Added

- Add `From` extended point to `PublicInputValue` [#573](https://github.com/dusk-network/plonk/issues/574)

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
- Fixes [#311](https://github.com/dusk-network/plonk/issues/311) - big_mul and big_mul_gate documentation nit.

## [0.3.1] - 05-10-20

### Added

- Method to change the `trim_params_size` for the `Circuit` trait.

## [0.3.0] - 05-10-20

### Changed

- `Circuit` trait API & usability improvements [#313](https://github.com/dusk-network/plonk/issues/313)

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

- Added `ProverKey` & `VerifierKey` to the public API as exported types.

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
- Serialization methods for the crate public structures &
  `serde` support.
- Add a `variable_base_scalar_mul` method using a variable base curve add gate.

### Removed

- `failure` for error support since has been deprecated.

### Changed

- `add_witness_to_circuit_description` requires now just to send
  a `Scalar` and returns a constant & constrained witness `Variable`.
- Update `add_witness_to_circuit_description` fn sig [#282](https://github.com/dusk-network/plonk/issues/282), [#284](https://github.com/dusk-network/plonk/issues/284)
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

<!-- VERSIONS -->
[unreleased]: https://github.com/dusk-network/plonk/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/dusk-network/plonk/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/dusk-network/plonk/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/dusk-network/plonk/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/dusk-network/plonk/compare/v0.8.2...v0.9.0
[0.8.2]: https://github.com/dusk-network/plonk/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/dusk-network/plonk/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/dusk-network/plonk/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dusk-network/plonk/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/dusk-network/plonk/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/dusk-network/plonk/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/dusk-network/plonk/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/dusk-network/plonk/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dusk-network/plonk/compare/v0.3.6...v0.4.0
[0.3.6]: https://github.com/dusk-network/plonk/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/dusk-network/plonk/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/dusk-network/plonk/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/dusk-network/plonk/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/dusk-network/plonk/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/dusk-network/plonk/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/dusk-network/plonk/compare/v0.2.11...v0.3.0
[0.2.11]: https://github.com/dusk-network/plonk/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/dusk-network/plonk/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/dusk-network/plonk/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/dusk-network/plonk/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/dusk-network/plonk/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/dusk-network/plonk/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/dusk-network/plonk/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/dusk-network/plonk/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/dusk-network/plonk/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/dusk-network/plonk/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/dusk-network/plonk/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dusk-network/plonk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/plonk/releases/tag/v0.1.0
