# Plonk — AI Agent Instructions

## Project Overview

**dusk-plonk** is a pure Rust implementation of the PLONK ZK proving system over BLS12-381 with a KZG10 polynomial commitment scheme and custom gates. Single crate, no workspace.

### Key Directories

| Directory | Purpose |
|-----------|---------|
| `src/` | Library source |
| `src/composer/` | Circuit building, constraint system, gates |
| `src/proof_system/` | Proving and verification, widgets |
| `src/commitment_scheme/` | KZG10 polynomial commitments |
| `src/fft/` | Fast Fourier Transform, polynomial arithmetic |
| `tests/` | Integration tests |
| `benches/` | Benchmarks |
| `examples/` | Usage example (`circuit.rs`) |
| `docs/` | PLONK specs PDF |

## Commands

Run `make help` to list all available targets. Key points:

- **Always use `make` targets**: the Makefile is the source of truth for
  build, test, lint and docs commands. Each CI job runs one target.
- **Tests MUST use `--release`**: debug mode takes up to an hour for proof
  tests. `make test` does this. Run a single test with
  `cargo test --release <test_name>`.
- `make fmt` needs the nightly toolchain.
- Before a PR, run `make cq` and `make test`.

## Architecture

Widget-based prover with a Turbo composer. Circuits implement the `Circuit` trait, which defines `circuit(&self, composer: &mut Composer)` to build constraints. The `Compiler` takes a circuit + public parameters and produces prover/verifier pairs.

**Core flow**: Circuit -> Composer (constraint system) -> Compiler -> ProverKey/VerifierKey -> Proof -> Verify.

**Widget types** (in `proof_system/widget/`): arithmetic, logic, range, ECC, permutation — each handles a category of constraints during proving and verification.

**Commitment scheme**: KZG10 with a structured reference string (SRS). The `PublicParameters` type holds the SRS and is needed for compilation.

## Feature Flags

| Feature | Purpose | Default |
|---------|---------|---------|
| `std` | Enables rayon parallelism | Yes |
| `alloc` | Core feature for proof construction/verification | No |
| `debug` | Runtime debugger with CDF output | No |
| `rkyv-impl` | rkyv serialization support | No |

## Elevated Care Zone

This is a cryptographic crate — soundness bugs break consensus and privacy. Work with extra diligence.

- **Verify**: `make test` (covers both default and all-features) and `make no-std`
- **Watch**: polynomial arithmetic, commitment opening proofs, transcript (Fiat-Shamir) binding, gate constraint enforcement

## Conventions

- **`no_std` compatible**: the crate supports `no_std` with `alloc`. Don't add `std` imports outside feature gates.
- **Release mode testing**: always `--release` for proof tests
- **Feature gating**: don't pull gated dependencies into default features
- **Clippy**: don't suppress warnings — fix the underlying issue

## Change Propagation

Changes to plonk ripple to downstream crates — `phoenix/circuits`, `poseidon-merkle`, `rusk` to name a few. Keep this in mind when making code changes, but no need to verify downstream for non-code changes.

## Git

**Branches**: branch from `master`. Don't push to `master` directly.
**Commits**: follow the style of recent commits in the repo.

## Changelog

Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes only. Exclude tests, CI, tooling, and refactors.

- One fact per entry. Name the public item and behavior, including the affected released item if breaking. Leave implementation, rationale, consequences, and migration to the linked issue.
- Use existing `Added`, `Changed`, or `Removed` sections. Use `Fixed` only for released bugs. Correct unreleased bugs in their original entry.
- Link only the GitHub issue, not the PR. Match existing link style and define references below. Preserve other entries and follow [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and Markdown blank-line spacing.
