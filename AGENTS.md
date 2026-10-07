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

Add an entry to `CHANGELOG.md` under `[Unreleased]` only for a change that users of the crate can see. Tests, CI, tooling and internal refactors get no entry.

- Write one fact per entry, in one sentence. Two facts get two entries.
- Name what changed at the crate's surface: the public item and its new behavior. Do not describe how the code does it.
- Name the released item that a breaking change breaks.
- Keep the reason, the consequences and the migration steps in the linked issue, not in the entry.
- Choose the section by the effect on users: new things go under `Added`, changed behavior goes under `Changed`, and removed things go under `Removed`. Use `Fixed` only for a bug that a release had. For a bug in unreleased code, correct the entry that added that code.
- Link the tracking GitHub issue, not the PR, and no other tracking identifier. Use the link format that the file already uses. A reference link needs its definition in the block at the bottom.
- Add to the existing section headings, and leave the other entries as they are.
- Use the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
- Follow standard markdown formatting: separate headings from surrounding content with blank lines, leave a blank line before and after lists, and never have two headings back-to-back without a blank line between them.
