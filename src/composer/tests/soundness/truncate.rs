// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regression for `component_truncate`'s input binding.
//!
//! `component_truncate` is the purpose-built primitive for deriving a truncated
//! value, in place of `append_logic_xor::<N>(x, ZERO)`. The motivating concern:
//! a truncation gadget must bind its output to its input, and this test pins
//! that binding down directly. `component_truncate` binds `low` to `witness`
//! through the relation `witness = high * 2^num_bits + low` plus a canonical
//! `< r` guard, so a prover cannot satisfy the gate layout (and so the verifier
//! key) with a `low` decoupled from `witness`.
//!
//! Exhibiting a decoupling attempt means emitting `component_truncate`'s exact
//! gate layout with attacker-chosen `low`/`high` witnesses — which uses
//! crate-private composer internals, hence this test lives in-crate. Each case
//! is a full `compile -> prove` round-trip against the verifier key compiled
//! from the honest gadget: the control proves and verifies, every forgery is
//! rejected at proving because the binding makes its assignment unsatisfiable.
//!
//! For a forgery's rejection to mean anything, it has to come from the
//! constraint under test and nothing else. Two properties pin that down. First,
//! the circuit's input and output are **public inputs**, not baked-in
//! constants, so the emitted gate layout is independent of the values a case
//! proves with; every case then explicitly asserts its layout is identical to
//! the honest one, which fails the moment the production gadget stops emitting
//! a constraint the forgery fork emits. Second, rejection is matched against
//! the error an unsatisfiable assignment surfaces as — an `InvalidCircuitSize`,
//! or any other proving error, fails the test rather than passing it.
//!
//! The binding is exercised at `N = 250` (the truncated-Poseidon
//! Schnorr-challenge width), at `N = 254` (the compile-time cap and tightest
//! canonical-guard margin — the only width where `r_high = 1`), and at an odd
//! `N = 251` to cover the odd-width range-check path.

use dusk_bls12_381::BlsScalar;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::support::{assert_rejected, assert_verifies, fits, pow, truncate};
use crate::composer::bits::recompose_bits;
use crate::composer::{Composer, Constraint, Witness};
use crate::prelude::{
    Circuit, Compiler, Error, Prover, PublicParameters, Verifier,
};

// An attacker's fork of [`Composer::component_truncate`]: byte-identical gate
// emission, except the returned `low` (and the paired `high`) are sourced from
// attacker-chosen values rather than derived from `witness`. Models a malicious
// prover emitting the honest gate layout while filling the witnesses with
// values that decouple the output from the input. Because the gadget binds
// `low`/`high` to `witness`, any such decoupled assignment is unsatisfiable.
fn forge_truncate<const N: usize>(
    composer: &mut Composer,
    witness: Witness,
    forged_low: BlsScalar,
    forged_high: BlsScalar,
) -> Witness {
    let high_bits = 255 - N;

    let low = composer.append_witness(forged_low);
    composer.range_check(low, N);

    let high = composer.append_witness(forged_high);
    composer.range_check(high, high_bits);

    let recomposed = composer
        .gate_add(Constraint::new().left(pow(N)).right(1).a(high).b(low));
    composer.assert_equal(recomposed, witness);

    composer.assert_canonical_truncation(high, low, N);

    low
}

// Either the honest gadget or, when `forge` is set, the layout-identical fork
// above.
//
// Both the input and the truncation output are exposed as public inputs, so the
// statement a proof makes is the full pair `(input, low)` — a forgery has to
// carry a `low` that is not the truncation of the `input` it declares. Pinning
// the input as a public input rather than as a circuit constant is what keeps
// the emitted gate layout independent of the values: `assert_equal_constant`
// would bake the input into a `q_c` selector, so a case proving with a
// different input than the one compiled would be rejected by that selector
// alone, masking whether the constraint under test fired at all.
struct TruncCircuit<const N: usize> {
    input: BlsScalar,
    claimed_low: BlsScalar,
    forge: Option<(BlsScalar, BlsScalar)>,
}

impl<const N: usize> Default for TruncCircuit<N> {
    // The default values are arbitrary: gate emission is witness-independent,
    // so the compiled circuit description keys off `N` alone. A full-width,
    // near-modulus value is chosen only to make the intent legible.
    fn default() -> Self {
        let input = -BlsScalar::one();
        Self {
            input,
            claimed_low: truncate(input, N),
            forge: None,
        }
    }
}

impl<const N: usize> Circuit for TruncCircuit<N> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let witness = composer.append_public(self.input);

        let low = match self.forge {
            None => composer.component_truncate::<N>(witness),
            Some((forged_low, forged_high)) => {
                forge_truncate::<N>(composer, witness, forged_low, forged_high)
            }
        };

        let pi = composer.append_public(self.claimed_low);
        composer.assert_equal(low, pi);

        Ok(())
    }
}

// Compile a verifier key from the HONEST gadget at `N`, then confirm
// the control proves and verifies while two distinct decoupling forgeries —
// emitting the identical gate layout — are rejected at proving.
fn assert_binding_holds<const N: usize>(
    pp: &PublicParameters,
    rng: &mut StdRng,
) {
    let num_bits = N;
    let high_bits = 255 - N;
    let label = b"component-truncate-soundness";

    let (prover, verifier): (Prover, Verifier) =
        Compiler::compile::<TruncCircuit<N>>(pp, label).expect("compile");

    // --- CONTROL: honest prover, honest public input, proves and verifies.
    // A wide, near-modulus input, so this also pins that honest inputs far
    // above the truncation width are still accepted. ---
    let input = -BlsScalar::one();
    let honest = TruncCircuit::<N> {
        input,
        claimed_low: truncate(input, num_bits),
        forge: None,
    };
    let honest_low = honest.claimed_low;
    assert_eq!(
        assert_verifies(&prover, &verifier, rng, &honest),
        vec![input, honest_low],
        "honest public inputs == (input, truncate(input))"
    );

    // --- FORGERY A: decoupled `low`, `high` chosen to satisfy the linear
    // binding in-field. The `low` range check passes, but `high` is then a
    // full-width field element and fails its range check. ---
    let forged_low = BlsScalar::from(0x00C0_FFEE_u64);
    assert_ne!(forged_low, honest_low, "forged low must differ from honest");
    assert!(
        fits(forged_low, num_bits),
        "forged low must clear its range check",
    );
    let pow_inverse = pow(num_bits).invert().expect("2^num_bits is invertible");
    let matching_high = (input - forged_low) * pow_inverse;
    assert!(
        !fits(matching_high, high_bits),
        "FORGERY A is the out-of-range-high case; its high must not fit",
    );
    let forgery_a = TruncCircuit::<N> {
        input,
        claimed_low: forged_low,
        forge: Some((forged_low, matching_high)),
    };
    assert_rejected(&prover, rng, &honest, &forgery_a, "FORGERY A");

    // --- FORGERY B: the canonical alias. The non-canonical split of
    // `input + r` clears BOTH range checks and the linear binding (it
    // recomposes to `input` in the field), yet represents a value >= r. It
    // splits at exactly `high == r_high`, so it is the guard's *low* half —
    // `is_top * (r_low - low)` — that rejects it; FORGERY C below covers the
    // high half.
    //
    // The alias only exists for a small input: `input + r` must still split
    // into a high part that fits `high_bits`, which rules out the control's
    // near-modulus value. The input is a public input, so using a different one
    // here does not change the gate layout — asserted below. ---
    let aliased_input = BlsScalar::one();
    let aliased_honest_low = truncate(aliased_input, num_bits); // == 1
    let modulus_bits = (-BlsScalar::one()).to_bits();
    let r_low = recompose_bits(&modulus_bits, 0, num_bits);
    let r_high = recompose_bits(&modulus_bits, num_bits, 256);
    // `modulus_bits` are the bits of `r - 1`, so `1 + r` splits as
    // `r_high * 2^num_bits + (r_low + 2)`, with no carry into the high part.
    let alias_low = r_low + BlsScalar::from(2u64);
    let alias_high = r_high;
    // The split must recompose to the input in-field (so it clears the linear
    // binding) yet differ from the honest low (so it is a genuine forgery).
    assert_eq!(
        alias_high * pow(num_bits) + alias_low,
        aliased_input,
        "alias must recompose to the input in-field"
    );
    assert_ne!(
        alias_low, aliased_honest_low,
        "aliased low must differ from honest"
    );
    // Both range checks must pass, so the canonical guard is the only remaining
    // reason the assignment can be rejected.
    assert!(
        fits(alias_low, num_bits),
        "aliased low must clear its range check",
    );
    assert!(
        fits(alias_high, high_bits),
        "aliased high must clear its range check",
    );
    let forgery_b = TruncCircuit::<N> {
        input: aliased_input,
        claimed_low: alias_low,
        forge: Some((alias_low, alias_high)),
    };
    assert_rejected(&prover, rng, &honest, &forgery_b, "FORGERY B");

    // --- FORGERY C: the same `+ r` alias, taken on the high side. Every case
    // above splits at `high <= r_high`, so none of them reaches the guard's
    // `range_check(diff, high_bits)` on `diff = r_high - high` — the one
    // constraint that keeps `high` from climbing past `r_high` into the rest of
    // its range check's interval.
    //
    // With `input = 2^num_bits` the split `(r_high + 1, r_low + 1)` recomposes
    // to `r + 2^num_bits == input` in the field, clears both range checks, and
    // leaves `diff` non-zero — so `is_top` is 0, the guard's low half is
    // vacuously 0, and only the `diff` range check underflows. ---
    let high_alias_high = r_high + BlsScalar::one();

    // At `N = 254`, `r_high` is 1 against a 1-bit check, so `r_high + 1` is
    // already out of range and `range_check(high, high_bits)` rejects the split
    // before the guard sees it. There is no reachable high-side alias to forge
    // at that width; the case applies at every other one.
    if fits(high_alias_high, high_bits) {
        let high_input = pow(num_bits);
        let high_alias_low = r_low + BlsScalar::one();
        assert_eq!(
            high_alias_high * pow(num_bits) + high_alias_low,
            high_input,
            "high-side alias must recompose to the input in-field"
        );
        assert_ne!(
            high_alias_low,
            truncate(high_input, num_bits), // == 0
            "high-side aliased low must differ from honest"
        );
        assert!(
            fits(high_alias_low, num_bits),
            "high-side aliased low must clear its range check",
        );
        let forgery_c = TruncCircuit::<N> {
            input: high_input,
            claimed_low: high_alias_low,
            forge: Some((high_alias_low, high_alias_high)),
        };
        assert_rejected(&prover, rng, &honest, &forgery_c, "FORGERY C");
    }
}

#[test]
fn truncation_output_is_bound_to_its_input() {
    let mut rng = StdRng::seed_from_u64(0x7_2c47e);
    let pp = PublicParameters::setup(1 << 10, &mut rng).expect("setup");

    // 250 bits: the truncated-Poseidon Schnorr-challenge width.
    assert_binding_holds::<250>(&pp, &mut rng);

    // 254 bits: the compile-time cap and tightest canonical-guard margin, the
    // only width where `r_high = 1`.
    assert_binding_holds::<254>(&pp, &mut rng);

    // 251 bits: an odd width, exercising the odd-width range-check path.
    assert_binding_holds::<251>(&pp, &mut rng);
}
