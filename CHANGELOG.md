# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed 

- Modify the prover to match the paper [#831]
- Modify the verifier to match the paper [#831]
- Rename some variables to match the paper [#831]
- Modify the parallelization to have a faster verifier [#834]

### Removed

- Remove docs [#819]
- Remove unused `Evaluations` struct

## [0.19.2] - 2024-03-27

### Added

- Add `zeroize` as an optional dependency [#818]
- Add `zeroize` feature [#818]
- Add `Zeroize` trait implementation for `Witness` behind `zeroize` feature [#818]

## [0.19.1] - 2024-02-28

### Changed

- Reduce hades constants count in circuit compression from 960 to 335 [#813]

### Added

- Add `Default` trait for `Witness` [#815]

## [0.19.0] - 2024-01-03

### Fixed

- Fix inconsistency in gate ordering of arithmetic verifier key [#797]
- Fix leading coefficients might be zero [#796]
- Fix tests when default features are turned off by placing them behind the `alloc` feature

### Changed

- Improve InvalidCircuitSize error [#792]
- Hide all modules except 'prelude' [#782]
- Turn `Composer` trait into a struct [#802]
- Rename `Arithmetization` to `Gate` [#802]
- Change internal module structure [#805]:
  - Move compiler module to root
  - Move prover and verifier modules under compiler
  - Move compress module under composer
  - Move constraint_system module under composer
  - Move permutation module under composer
- Change API for circuit (de-)compression [#804]

### Removed

- Remove `Builder` struct with introduction of `Composer` struct [#802]
- Remove example from README in favor of an actual example in the example directory that is behind the `alloc` feature [#346]

### Added

- Add example for circuit creation [#346]

## [0.18.0] - 2023-12-13

### Changed

- dusk-bls12_381 -> 0.13
- dusk-jubjub -> 0.14

## [0.17.0] - 2023-11-1

### Added

- Add `JubJubScalarMalformed` error [#784]
- Add blinding factors to the quotient polynomial [#773]

### Changed

- Update `criterion` dev-dependency to 0.5
- Fix clippy warnings [#774]
- Rename `composer::Polynomial` to `composer::Arithmetization`
- Rename `fft::{Polynomial as FftPolynomial}` to `fft::Polynomial`

## [0.16.0] - 2023-10-11

### Added

- Add `size` method to the `Circuit` trait [#767]
- Add `ff` dependency

### Removed

- Remove `PublicParameters` from parameters for circuit compression [#767]
- Remove `canonical` and `canonical_derive` dependency
- Remove `canon` feature

### Changed

- update `dusk-bls12_381` dependency to "0.12"
- update `dusk-jubjub` dependency to "0.13"

## [0.15.0] - 2023-08-30

### Fixed

- Fix panic when creating proof for circuit with different circuit size [#760]
- Fix panic when testing in debug mode [#763]

### Removed

- Remove 'setup' funcion from common test module [#763]

### Changed

- Change range and logic component to be generic over the const `BIT_PAIRS` [#763]

## [0.14.1] - 2022-06-28

### Added

- Add `compress` to compiler [#752]

## [0.14.0] - 2022-04-06

### Added

- Add and restructure tests for `assert_equal_point` [#725]
- Add and restructure tests for `assert_equal_public_point` [#727]
- Add and restructure tests for `append_gate` [#737]
- Add and restructure tests for `assert_equal` and `assert_equal_constant` [#733]
- Add and restructure tests for logic component [#734]
- Add and restructure tests for range component [#735]
- Add and restructure tests for boolean and select components [#731]
- Add tests for `gate_add` and `gate_mul` [#736]
- Add and restructure tests for `component_decomposition` [#738]
- Add `Compile::compress` and `Compile::decompress` [#752]

### Removed

- Remove `bit_iterator` macro [#632]

### Fixed

- Fix negation of public input values when using `composer.append_public` [#717]
- Fix `assert_equal_point` method [#720]
- Fix negation of constant in `append_equal_constant` [#728]
- Fix negation of public point coordinates in `assert_equal_public_point` [#728]
- Fix `ProverKey::serialization_size` and number of coefficients in a constraint [#743]
- Fix range gate for `bit_num = 0` [#746]

## [0.13.1] - 2022-10-26

### Fixed

- Remove manual implementation of `CheckBytes` for `ArchivedProverKey`. This
is necessary since `rkyv/validation` was required as a bound.

## [0.13.0] - 2022-10-19

### Added

- Add support for `rkyv-impl` under `no_std`

### Changed

- Update `dusk-cdf` to 0.5 [#709]

## [0.12.0] - 2022-08-17

### Added

- Add makefile rule to render docs locally [#567]
- `rkyv` implementation behind feature gate [#697]

### Changed

- Fix math latex rendering on docs.rs [#567]
- Update `dusk-bls12_381` to version `0.11`
- Update `dusk-jubjub` to version `0.12`

## [0.11.0] - 2022-06-15

### Added

- Add the blinding factors to provide Zero-Knowledge [#650]
- Add the `public inputs` into the transcript [#676]

### Changed

- Update CHANGELOG issue links and release dates [#688]
- Change variable names for more consistency with the paper [#631]
- Change `append_constant` to accept generic input [#672]
- Change `variable` to `witness` in permutation functions [#681]
- Change the `prover` and the `verifier` so that it reflects the original Plonk implementation and not plonkup [#684]

### Removed

- Remove `hash_tables` module which had been moved to zelbet [#663]
- Remove all `plonkup` related code [#684]

### Fixed

- Fix `logic_gate` for `bit_num` = 256 [#678]
- Fix error when compiling some circuits [#690]

## [0.10.0] - 2022-02-24

## Changed

- Update canonical and canonical-derive to 0.7 [#666]
- Update dusk-bls12_381 to 0.9 [#666]
- Update jubjub to 0.11 [#666]
- Update rust edition to 2021 [#665]

## [0.9.2] - 2022-01-06

### Added

- Add `circuit::verify` to `Circuit` module. [#657]

## [0.9.1] - 2022-01-05

### Added

- Add support for rendering LaTeX in the docs [#567]
- Add `append_public_witness` to `TurboComposer`. [#654]

## [0.9.0] - 2021-11-10

### Added

- Add back benchmarks to the crate. [#555]
- Add `ProverKey::num_multiset` [#581]
- Add alloc feature for lookup Vec structs [#582]
- Add test coverage for polynomial evaluations [#586]
- Add `Witness` by removing `AllocatedScalar`. [#588]
- Add missing dummy constraints in test [#592]
- Add codeconv config [#594]
- Add `Constraint` for circuit description. [#608]
- Add public unsafe `evaluate_witness()` to the composer [#612]

### Changed

- Change `StandardComposer` to `TurboComposer`. [#288]
- Change to use `From<JubJubScalar>` for BlsScalar [#294]
- Change unit tests as integration tests when possible [#500]
- Change to arrays some tuples in permutation module [#562]
- Change `poly_gate` to init lookup wire with zero [#578]
- Change `TurboComposer` to consistent API. [#587]
- Change `plonkup_gate` to use public inputs. [#584]
- Change coverage to use less compile flags. [#605]
- Change `Constraint` to accept witness args. [#624]

### Fixed

- Fix the document references and typos [#533]
- Fix if condition to match [#545]
- Fix `Prover::preprocess` circuit size for plookup [#580]
- Fix ignored tests by reincluding them [#593]
- Fix benches and make CI fail if they don't compile [#610]
- Fix several small nits and unnecessary operations [#611]
- Fix clippy reports [#622]

### Removed

- Remove old perm-computation fns from perm module [#515]
- Remove unused `plonkup` module. [#583]
- Remove the re-export of jubjub and bls libs [#558]
- Remove `Plonkup3Arity` [#589]
- Remove windows from CI. [#616]

## [0.8.2] - 2021-09-17

### Added

- Add `From` extended point to `PublicInputValue` [#573]

## [0.8.1] - 2021-06-07

### Added

- Add `zero_var` to composer [#526]
- Add `add_affine_to_circuit_description`to composer [#534]

### Removed

- Remove `external_doc` and `nightly` feature [#536]

## [0.8.0] - 2021-06-03

### Added

- Add `alloc` feature to the crate [#345]
- Add `rayon` behind `std` feature to boost proving performance [#512]
- Add `rayon` behind `std` feature to boost verifying performance [#514]
- Add alternative getters for `OpeningKey` & `CommitKey` in `PublicParameters` [#510]

### Changed

- Change `constraint_system/ecc` module API improving usability and consistency [#456]
- Change the crate to be `no_std` [#350]
- Replace `Commitment::from_projective` for `From` trait impl  [#433]
- Update `canonical` from `0.5` to `0.6` [#494]

### Removed

- Remove trimming step from `Circuit::Verify_proof` [#510]

## [0.7.0] - 2021-04-06

### Added

- Implement `VerifierData` structure. [#466]

### Fixed

- Fix circuit debuggger compilation issues. [#488]
- Fix import paths for lib components. [#489]

## [0.6.1] - 2021-03-12

### Changed

- Change `PublicParameters::trim` visibility to `pub`. [#460]
- Change `StandardComposer::construct_dense_pi_vec` visibility to `pub`. [#461]

## [0.6.0] - 2021-03-11

### Added

- Implement `dusk_bytes::Serializable` for all possible structures that need serde. [#352]
- Introduced a new type that unifies the Public Inputs `PublicInputValue`. [#416]
- Impl `padded_circuit_size` for `VerifierKey` [#351]
- Impl a generic method that can verify Proofs of any `Circuit`. [#396]

### Removed

- Remove `Canon` impl for `Proof`. [#450]
- Remove serde support completely from the repo. [#353]
- Removed previous implementations attached to `PublicInputValues`. [#416]
- Deprecated `anyhow` and `thiserror`. [#343]
- Remove `serialisation` module and use single serialization fn's. [#347]
- Remove uncessary `match` branch for `var_c` [#414]
- Remove legacy fns and move to test modules the only-for-testing ones. [#434]

### Changed

- Constrained as much as possible the visibility of fns, structs and it's fields [#438]
- Store the sparse repr of the PI and positions in a `BTreeMap` [#427]
- Transcript Init and trim size are associated constants of the Circuit trait [#351]
- Replace `collections::HashMap` by `hashbrown::HashMap`. [#424]
- `Circuit` trait now only requires `padded_circuit_size` for trimming. [#351]
- Remove `verify_proof` & `build_pi` from `Circuit`. [#396]
- Update API naming conventions to be standard across the crate. [#354]
- Updated the native errors to all originate from the same enum. [#343]

## [0.5.1] - 2021-02-02

### Changed

- Implement `Clone` for `PublicParameters` [#383]

## [0.5.0] - 2021-01-27

### Changed

- Upgrade canonical to v0.5 [#371]
- Upgrade dusk-bls12_381 to v0.6
- Upgrade dusk-jubjub to v0.8

## [0.4.0] - 2021-01-26

### Fixed

- Heavy data structures from unchecked [#332]

### Changed

- Refactored to/from_bytes criteria for some structs [#333]
- API breaking
- Implement to/from unchecked bytes for public parameters [#332]

## [0.3.6] - 2020-12-17

### Added

- To/From bytes impl for `PublicInput`.

### Changed

- Changed `compute_permutation_poly` to simpler version.

## [0.3.5] - 2020-11-25

### Changed

- Changed `Proof` & `ProofEvaluations` byte conversion fn signatures.

### Added

- Implemented `Canon` for `Proof`.

## [0.3.4] - 2020-11-02

### Changed

- dusk-jubjub update to `v0.5.0` with API renaming
- dusk-bls12_381 update to `v0.3.0` with API renaming

## [0.3.3] - 2020-11-02

### Added

- `canon` feature to manage `Canon` derivations usage in ecc libs.

### Changed

- dusk-jubjub update to `v0.4.0`
- dusk-bls12_381 update to `v0.2.0`

## [0.3.2] - 2020-10-29

### Changed

- dusk-bls12_381 update to `v0.1.5`
- dusk-jubjub update to `v0.3.10`
- Fixes [#311]
- big_mul and big_mul_gate documentation nit.

## [0.3.1] - 2020-10-05

### Added

- Method to change the `trim_params_size` for the `Circuit` trait.

## [0.3.0] - 2020-10-05

### Changed

- `Circuit` trait API & usability improvements [#313]

## [0.2.11] - 2020-09-29

### Changed

- Now `Circuit` inputs are set in the circuit structure as `Option<T>`.
- Make `PublicInput::value()` fn public.
- Make pi_builder return `Result<T>`
- Refactored examples for the `Circuit` trait impl
  according to the new changes.

### Removed

- Removed `CircuitInputs` from the crate.

## [0.2.10] - 2020-09-23

### Added

- Added `CircuitBuilder` trait and a example for it.

## [0.2.9] - 2020-09-11

### Added

- Added `ProverKey` & `VerifierKey` to the public API as exported types.

### Changed

- Use `dusk-bls12_381 v0.1.4`.
- Use `dusk-jubjub v0.3.8`.

## [0.2.8] - 2020-08-25

### Added

- Add a `variable_base_scalar_mul` method using a variable base curve add gate.

### Changed

- `ecc::scalar_mul` now named fixed_base_scalar_mul

## [0.2.7] - 2020-08-13

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
- Update `add_witness_to_circuit_description` fn sig [#282], [#284]
- dusk-jubjub version updated to 0.3.6
- `ecc::scalar_mul` now named fixed_base_scalar_mul

## [0.2.6] - 2020-08-03

### Changed

- Make public inputs vector publicly accessible.

## [0.2.5] - 2020-07-31

### Changed

- ECC Point from `ecc:scalar_mul` should have its attributes exposed.

## [0.2.4] - 2020-07-29

### Changed

- Changed `dusk-jubjub` version to `v0.3.5` to fix Fr random gen.

## [0.2.3] - 2020-07-28

### Changed

- Changed `dusk-jubjub` version to `v0.3.4` to update dhke generation.

## [0.2.2] - 2020-07-25

### Added

- Method to create constrained witness values. @CPerezz

### Changed

- Visibility of the `Proof::verify()` fn to `pub(crate)`. @CPerezz
- Changed `dusk-jubjub` version to `v0.3.3` since `v0.3.2` was yanked.

## [0.2.1] - 2020-07-24 [yanked]

### Added

- Method to create constrained witness values. @CPerezz

### Changed

- Visibility of the `Proof::verify()` fn to `pub(crate)`. @CPerezz

## [0.2.0] - 2020-07-20

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

## [0.1.0] - 2020-04-25

### Added

- PLONK algorithm implementation.
- Example folders.
- Doc notes with kateX.
- KZG10 polynomial commitment scheme implementation.
- fft module with Polynomial ops implemented.
- Proof system module.

<!-- ISSUES -->
[#834]: https://github.com/dusk-network/plonk/issues/834
[#831]: https://github.com/dusk-network/plonk/issues/831
[#819]: https://github.com/dusk-network/plonk/issues/819
[#818]: https://github.com/dusk-network/plonk/issues/818
[#815]: https://github.com/dusk-network/plonk/issues/815
[#813]: https://github.com/dusk-network/plonk/issues/813
[#805]: https://github.com/dusk-network/plonk/issues/805
[#804]: https://github.com/dusk-network/plonk/issues/804
[#802]: https://github.com/dusk-network/plonk/issues/802
[#797]: https://github.com/dusk-network/plonk/issues/797
[#796]: https://github.com/dusk-network/plonk/issues/796
[#792]: https://github.com/dusk-network/plonk/issues/792
[#784]: https://github.com/dusk-network/plonk/issues/784
[#782]: https://github.com/dusk-network/plonk/issues/782
[#773]: https://github.com/dusk-network/plonk/issues/773
[#774]: https://github.com/dusk-network/plonk/issues/774
[#763]: https://github.com/dusk-network/plonk/issues/763
[#760]: https://github.com/dusk-network/plonk/issues/760
[#752]: https://github.com/dusk-network/plonk/pull/752
[#738]: https://github.com/dusk-network/plonk/issues/738
[#746]: https://github.com/dusk-network/plonk/issues/746
[#736]: https://github.com/dusk-network/plonk/issues/736
[#735]: https://github.com/dusk-network/plonk/issues/735
[#734]: https://github.com/dusk-network/plonk/issues/734
[#743]: https://github.com/dusk-network/plonk/issues/743
[#737]: https://github.com/dusk-network/plonk/issues/737
[#733]: https://github.com/dusk-network/plonk/issues/733
[#731]: https://github.com/dusk-network/plonk/issues/731
[#728]: https://github.com/dusk-network/plonk/issues/728
[#727]: https://github.com/dusk-network/plonk/issues/727
[#725]: https://github.com/dusk-network/plonk/issues/725
[#720]: https://github.com/dusk-network/plonk/issues/720
[#717]: https://github.com/dusk-network/plonk/issues/717
[#709]: https://github.com/dusk-network/plonk/issues/709
[#697]: https://github.com/dusk-network/plonk/issues/697
[#688]: https://github.com/dusk-network/plonk/issues/688
[#650]: https://github.com/dusk-network/plonk/issues/650
[#676]: https://github.com/dusk-network/plonk/issues/676
[#632]: https://github.com/dusk-network/plonk/issues/632
[#631]: https://github.com/dusk-network/plonk/issues/631
[#672]: https://github.com/dusk-network/plonk/issues/672
[#681]: https://github.com/dusk-network/plonk/issues/681
[#663]: https://github.com/dusk-network/plonk/issues/663
[#684]: https://github.com/dusk-network/plonk/issues/684
[#678]: https://github.com/dusk-network/plonk/issues/678
[#690]: https://github.com/dusk-network/plonk/issues/690
[#666]: https://github.com/dusk-network/plonk/issues/666
[#665]: https://github.com/dusk-network/plonk/issues/665
[#657]: https://github.com/dusk-network/plonk/issues/657
[#567]: https://github.com/dusk-network/plonk/issues/567
[#654]: https://github.com/dusk-network/plonk/issues/654
[#555]: https://github.com/dusk-network/plonk/issues/555
[#581]: https://github.com/dusk-network/plonk/issues/581
[#582]: https://github.com/dusk-network/plonk/issues/582
[#586]: https://github.com/dusk-network/plonk/issues/586
[#588]: https://github.com/dusk-network/plonk/issues/588
[#592]: https://github.com/dusk-network/plonk/issues/592
[#594]: https://github.com/dusk-network/plonk/issues/594
[#608]: https://github.com/dusk-network/plonk/issues/608
[#612]: https://github.com/dusk-network/plonk/issues/612
[#288]: https://github.com/dusk-network/plonk/issues/288
[#294]: https://github.com/dusk-network/plonk/issues/294
[#500]: https://github.com/dusk-network/plonk/issues/500
[#562]: https://github.com/dusk-network/plonk/issues/562
[#578]: https://github.com/dusk-network/plonk/issues/578
[#587]: https://github.com/dusk-network/plonk/issues/587
[#584]: https://github.com/dusk-network/plonk/issues/584
[#605]: https://github.com/dusk-network/plonk/issues/605
[#624]: https://github.com/dusk-network/plonk/issues/624
[#533]: https://github.com/dusk-network/plonk/pull/533
[#545]: https://github.com/dusk-network/plonk/pull/545
[#580]: https://github.com/dusk-network/plonk/issues/580
[#593]: https://github.com/dusk-network/plonk/issues/593
[#610]: https://github.com/dusk-network/plonk/issues/610
[#611]: https://github.com/dusk-network/plonk/issues/611
[#622]: https://github.com/dusk-network/plonk/pull/622
[#515]: https://github.com/dusk-network/plonk/issues/515
[#583]: https://github.com/dusk-network/plonk/issues/583
[#558]: https://github.com/dusk-network/plonk/issues/558
[#589]: https://github.com/dusk-network/plonk/issues/589
[#616]: https://github.com/dusk-network/plonk/issues/616
[#573]: https://github.com/dusk-network/plonk/issues/573
[#526]: https://github.com/dusk-network/plonk/issues/526
[#534]: https://github.com/dusk-network/plonk/issues/534
[#536]: https://github.com/dusk-network/plonk/issues/536
[#345]: https://github.com/dusk-network/plonk/issues/345
[#512]: https://github.com/dusk-network/plonk/issues/512
[#514]: https://github.com/dusk-network/plonk/issues/514
[#456]: https://github.com/dusk-network/plonk/issues/456
[#350]: https://github.com/dusk-network/plonk/issues/350
[#433]: https://github.com/dusk-network/plonk/issues/433
[#494]: https://github.com/dusk-network/plonk/issues/494
[#510]: https://github.com/dusk-network/plonk/issues/510
[#466]: https://github.com/dusk-network/plonk/issues/466
[#488]: https://github.com/dusk-network/plonk/issues/488
[#489]: https://github.com/dusk-network/plonk/issues/489
[#460]: https://github.com/dusk-network/plonk/issues/460
[#461]: https://github.com/dusk-network/plonk/issues/461
[#352]: https://github.com/dusk-network/plonk/issues/352
[#450]: https://github.com/dusk-network/plonk/issues/450
[#353]: https://github.com/dusk-network/plonk/issues/353
[#416]: https://github.com/dusk-network/plonk/issues/416
[#347]: https://github.com/dusk-network/plonk/issues/347
[#414]: https://github.com/dusk-network/plonk/issues/414
[#434]: https://github.com/dusk-network/plonk/issues/434
[#438]: https://github.com/dusk-network/plonk/issues/438
[#427]: https://github.com/dusk-network/plonk/issues/427
[#424]: https://github.com/dusk-network/plonk/issues/424
[#351]: https://github.com/dusk-network/plonk/issues/351
[#396]: https://github.com/dusk-network/plonk/issues/396
[#354]: https://github.com/dusk-network/plonk/issues/354
[#346]: https://github.com/dusk-network/plonk/issues/346
[#343]: https://github.com/dusk-network/plonk/issues/343
[#383]: https://github.com/dusk-network/plonk/issues/383
[#371]: https://github.com/dusk-network/plonk/issues/371
[#333]: https://github.com/dusk-network/plonk/issues/333
[#332]: https://github.com/dusk-network/plonk/issues/332
[#311]: https://github.com/dusk-network/plonk/issues/311
[#313]: https://github.com/dusk-network/plonk/issues/313
[#284]: https://github.com/dusk-network/plonk/issues/284
[#282]: https://github.com/dusk-network/plonk/issues/282

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/plonk/compare/v0.19.2...HEAD
[0.19.2]: https://github.com/dusk-network/plonk/compare/v0.19.1...v0.19.2
[0.19.1]: https://github.com/dusk-network/plonk/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/dusk-network/plonk/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/dusk-network/plonk/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/dusk-network/plonk/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/dusk-network/plonk/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/dusk-network/plonk/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/dusk-network/plonk/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/dusk-network/plonk/compare/v0.13.1...v0.14.0
[0.13.1]: https://github.com/dusk-network/plonk/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/dusk-network/plonk/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/dusk-network/plonk/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/dusk-network/plonk/compare/v0.10.0...v0.11.0
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
