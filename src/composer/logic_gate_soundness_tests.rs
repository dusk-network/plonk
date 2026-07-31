// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Soundness regression for `append_logic_component`'s input binding.
//!
//! The logic gadget once rebuilt its output from the bits of `a`/`b` without
//! wiring the input witnesses into any gate, so a cheating prover could satisfy
//! the identical gate layout (and so the same verifier key) with accumulators
//! decoupled from the inputs. `append_logic_component` now binds the inputs;
//! this test guards against a regression of that historical defect.
//!
//! Exhibiting such an assignment requires emitting the logic gate with forged
//! witnesses, which needs the crate-private logic selector — hence this test
//! lives in-crate rather than in `tests/`. It is a full
//! `compile -> prove -> verify` round-trip against the real public gadget.
//!
//! Every forgery goes through [`assert_rejected`], which requires it to
//! emit the honest gate layout and then to be rejected by an unsatisfied
//! constraint — so a rejection here can only come from the binding, never from
//! a layout mismatch or an unrelated proving error.

use core::cmp;

use rand::SeedableRng;
use rand::rngs::StdRng;

use super::soundness_support::{
    assert_rejected, assert_verifies, fits, truncate,
};
use super::*;
use crate::prelude::{Compiler, Prover, PublicParameters, Verifier};

// Inputs pinned to constants so they are identical for every prover. Both fit
// in 32 bits, so for `BIT_PAIRS = 16` the result is exactly `input_a ^
// input_b`.
fn input_a() -> BlsScalar {
    BlsScalar::from(0x0f0f_0ff0_u64)
}
fn input_b() -> BlsScalar {
    BlsScalar::from(0xffff_0000_u64)
}

// An attacker's fork of [`Composer::append_logic_component`]: byte-identical
// gate emission, except the `a`-bits are sourced from `forged` instead of
// `self[a]`, so the returned witness is decoupled from the input witness `a`.
// This models a malicious prover that emits the honest gate layout while
// filling the per-quad accumulators with values unrelated to the inputs.
//
// It mirrors `append_logic_component` exactly so that, once that gadget binds
// its accumulators to its inputs, this fork inherits the binding gates too and
// the decoupled assignment becomes unsatisfiable.
fn forge_logic_component<const BIT_PAIRS: usize>(
    composer: &mut Composer,
    a: Witness,
    b: Witness,
    forged: BlsScalar,
    is_component_xor: bool,
) -> Witness {
    let (d, left_acc_wit, right_acc_wit) =
        forge_logic_loop::<BIT_PAIRS>(composer, b, forged, is_component_xor);

    // Mirror the honest gadget's binding. The binding wires the REAL `a`/`b` to
    // the (forged) accumulators, so the forged assignment is now unsatisfiable.
    composer.bind_logic_accumulators::<BIT_PAIRS>(
        a,
        b,
        left_acc_wit,
        right_acc_wit,
    );

    d
}

// The gate-emission loop shared by every fork: emits the identical logic gates
// as `append_logic_component` but sources the `a`-bits from `forged`. Returns
// the output witness and the final left/right accumulator witnesses (so callers
// can attach the binding gates of their choice). Does NOT bind the inputs.
fn forge_logic_loop<const BIT_PAIRS: usize>(
    composer: &mut Composer,
    b: Witness,
    forged: BlsScalar,
    is_component_xor: bool,
) -> (Witness, Witness, Witness) {
    let num_bits = cmp::min(BIT_PAIRS * 2, 254);
    let num_quads = num_bits >> 1;

    let bls_four = BlsScalar::from(4u64);
    let mut left_acc = BlsScalar::zero();
    let mut right_acc = BlsScalar::zero();
    let mut out_acc = BlsScalar::zero();

    // The ONLY deviation from `append_logic_component`: `a`-bits come from
    // `forged`, not from `composer[a]`.
    let a_bits: Vec<_> = BitIterator8::new(forged.to_bytes())
        .skip(256 - num_bits)
        .collect();
    let b_bits: Vec<_> = BitIterator8::new(composer[b].to_bytes())
        .skip(256 - num_bits)
        .collect();

    let mut constraint = if is_component_xor {
        Constraint::logic_xor(&Constraint::new())
    } else {
        Constraint::logic(&Constraint::new())
    };

    for i in 0..num_quads {
        let idx = i * 2;

        let l = (a_bits[idx] as u8) << 1;
        let r = a_bits[idx + 1] as u8;
        let left_quad = l + r;
        let left_quad_bls = BlsScalar::from(left_quad as u64);

        let l = (b_bits[idx] as u8) << 1;
        let r = b_bits[idx + 1] as u8;
        let right_quad = l + r;
        let right_quad_bls = BlsScalar::from(right_quad as u64);

        let out_quad_bls = if is_component_xor {
            left_quad ^ right_quad
        } else {
            left_quad & right_quad
        } as u64;
        let out_quad_bls = BlsScalar::from(out_quad_bls);

        let prod_quad_bls = BlsScalar::from((left_quad * right_quad) as u64);

        left_acc = left_acc * bls_four + left_quad_bls;
        right_acc = right_acc * bls_four + right_quad_bls;
        out_acc = out_acc * bls_four + out_quad_bls;

        let wit_a = composer.append_witness(left_acc);
        let wit_b = composer.append_witness(right_acc);
        let wit_c = composer.append_witness(prod_quad_bls);
        let wit_d = composer.append_witness(out_acc);

        constraint = constraint.c(wit_c);
        composer.append_custom_gate(constraint);
        constraint = constraint.a(wit_a).b(wit_b).d(wit_d);
    }

    let left_acc_wit = constraint.witness(WiredWitness::A);
    let right_acc_wit = constraint.witness(WiredWitness::B);
    let d = constraint.witness(WiredWitness::D);
    let constraint = Constraint::new().a(left_acc_wit).b(right_acc_wit).d(d);
    composer.append_custom_gate(constraint);

    (d, left_acc_wit, right_acc_wit)
}

// One circuit shape; `forged_a` selects the prover.
//   None       -> honest gadget, result = input_a ^ input_b.
//   Some(bits) -> cheating fork, result = bits ^ input_b (decoupled from `a`).
#[derive(Default)]
struct ForgeCircuit {
    forged_a: Option<BlsScalar>,
}

impl Circuit for ForgeCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        const BIT_PAIRS: usize = 16; // operate on the low 32 bits

        // Pin both inputs so they cannot differ between provers.
        let a = composer.append_witness(input_a());
        let b = composer.append_witness(input_b());
        composer.assert_equal_constant(a, input_a(), None);
        composer.assert_equal_constant(b, input_b(), None);

        let result = match self.forged_a {
            None => composer.append_logic_xor::<BIT_PAIRS>(a, b),
            Some(bits) => {
                forge_logic_component::<BIT_PAIRS>(composer, a, b, bits, true)
            }
        };

        // Expose the result as a public input.
        let claimed = self.forged_a.unwrap_or_else(input_a) ^ input_b();
        let public = composer.append_public(claimed);
        composer.assert_equal(result, public);

        Ok(())
    }
}

#[test]
fn logic_xor_binds_output_to_inputs() {
    let mut rng = StdRng::seed_from_u64(0x10_91c);
    let pp =
        PublicParameters::setup(1 << 12, &mut rng).expect("public parameters");

    // Verifier key compiled from the HONEST gadget.
    let (prover, verifier): (Prover, Verifier) =
        Compiler::compile::<ForgeCircuit>(&pp, b"logic-gate-soundness")
            .expect("compile");

    let honest_result = input_a() ^ input_b();

    // Control: the honest gadget computes the true XOR, and it verifies.
    let honest = ForgeCircuit { forged_a: None };
    assert_eq!(
        assert_verifies(&prover, &verifier, &mut rng, &honest),
        vec![honest_result],
    );

    // Forge: same gate layout, accumulators decoupled from the constrained `a`.
    // Before the fix this proved and verified against the honest verifier key;
    // the binding now makes the assignment unsatisfiable.
    let forged_a = BlsScalar::from(0x1234_5678_u64);
    assert_ne!(forged_a ^ input_b(), honest_result);
    let forged = ForgeCircuit {
        forged_a: Some(forged_a),
    };

    assert_rejected(
        &prover,
        &mut rng,
        &honest,
        &forged,
        "decoupled accumulators",
    );
}

// ---------------------------------------------------------------------------
// Canonical-truncation regression (250-bit, the Poseidon width).
//
// Binding `input = high * 2^num_bits + acc` with `high` range-checked is not,
// by itself, canonical: the field equation also admits `input + r`, i.e. an
// attacker can pick `acc' = (input + r) mod 2^num_bits` with a matching small
// `high'` that still fits the range check. `bind_truncation_split` closes that
// with the `< r` guard. This forces exactly that alias assignment and requires
// it to be rejected, pinning the guard at the logic gadget's width — the
// `component_truncate` module covers the primitive itself.
// ---------------------------------------------------------------------------

// A small input, so the wrap's `high` stays inside the 5-bit range check.
fn wrap_input() -> BlsScalar {
    BlsScalar::from(7u64)
}

// `r mod 2^250` (the low part of the modulus).
fn modulus_low_250() -> BlsScalar {
    // `r - 1` has the same high bits as `r`; its low bit is 0, so
    // `(r - 1) mod 2^250 = (r mod 2^250) - 1`.
    truncate(-BlsScalar::one(), 250) + BlsScalar::one()
}

// The non-canonical truncation `acc' = (input + r) mod 2^250 != input`.
fn wrap_acc() -> BlsScalar {
    truncate(wrap_input() + modulus_low_250(), 250)
}

// The matching `high' = (input - acc') / 2^250`, which makes
// `high' * 2^250 + acc' == input` in the field.
fn wrap_high() -> BlsScalar {
    let pow = BlsScalar::pow_of_2(250);
    (wrap_input() - wrap_acc()) * pow.invert().expect("2^250 is invertible")
}

#[derive(Default)]
struct WrapCircuit {
    wrap: bool,
}

impl Circuit for WrapCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        const BIT_PAIRS: usize = 125; // 250-bit truncation
        const NUM_BITS: usize = 250;
        const HIGH_BITS: usize = 255 - NUM_BITS;

        let a = composer.append_witness(wrap_input());
        composer.assert_equal_constant(a, wrap_input(), None);

        let result = if self.wrap {
            // Forge the loop with the wrap accumulator, then attach the SAME
            // binding gates as the honest gadget, but force `high` to the wrap
            // value `high'` (the honest gadget would derive `high = 0` from
            // `a`).
            let (d, left_acc_wit, right_acc_wit) = forge_logic_loop::<BIT_PAIRS>(
                composer,
                Composer::ZERO,
                wrap_acc(),
                true,
            );

            let high = composer.append_witness(wrap_high());
            composer.range_check(high, HIGH_BITS);
            let pow = BlsScalar::pow_of_2(NUM_BITS as u64);
            let recomposed = composer.gate_add(
                Constraint::new().left(pow).right(1).a(high).b(left_acc_wit),
            );
            composer.assert_equal(recomposed, a);

            // Emit the canonical `< r` guard on the forged split too, so this
            // branch reproduces the honest gadget's exact gate layout (and so
            // its verifier key). The wrap accumulator recomposes to the integer
            // `input + r`, i.e. a value `>= r`, which is precisely what the
            // guard rejects: `(high', acc')` exceeds `(r_high, r_low)`
            // lexicographically, so one of the guard's range checks underflows
            // and the assignment is unsatisfiable. The rejection is therefore
            // the guard constraint firing — not a circuit-size mismatch — which
            // is what pins the guard's soundness at the logic-gadget width.
            composer.assert_canonical_truncation(high, left_acc_wit, NUM_BITS);

            // `b = 0` is bound honestly.
            composer.bind_truncated_input::<BIT_PAIRS>(
                Composer::ZERO,
                right_acc_wit,
            );

            d
        } else {
            composer.append_logic_xor::<BIT_PAIRS>(a, Composer::ZERO)
        };

        let claimed = if self.wrap {
            wrap_acc()
        } else {
            truncate(wrap_input(), 250)
        };
        let public = composer.append_public(claimed);
        composer.assert_equal(result, public);

        Ok(())
    }
}

#[test]
fn logic_xor_truncation_is_canonical() {
    // Sanity on the wrap construction. It has to be a genuine forgery that
    // clears every constraint except the canonical guard, so that the guard is
    // the only thing that can reject it.
    let honest_low = truncate(wrap_input(), 250);
    assert_ne!(
        wrap_acc(),
        honest_low,
        "wrap accumulator must differ from honest"
    );
    assert!(
        fits(wrap_acc(), 250),
        "acc' must be < 2^250, the bound the logic gate imposes on it",
    );
    assert!(
        fits(wrap_high(), 5),
        "high' must clear the 5-bit range check"
    );
    assert_eq!(
        wrap_high() * BlsScalar::pow_of_2(250) + wrap_acc(),
        wrap_input(),
        "the wrap split must recompose to the input in-field",
    );

    let mut rng = StdRng::seed_from_u64(0x10_91d);
    let pp =
        PublicParameters::setup(1 << 12, &mut rng).expect("public parameters");
    let (prover, verifier): (Prover, Verifier) =
        Compiler::compile::<WrapCircuit>(&pp, b"logic-gate-wrap")
            .expect("compile");

    // Control: honest prover verifies.
    let honest = WrapCircuit { wrap: false };
    assert_eq!(
        assert_verifies(&prover, &verifier, &mut rng, &honest),
        vec![honest_low],
    );

    // The `+ r` alias must not yield a verifying proof. It clears both range
    // checks and the linear binding, so the canonical guard is the only
    // constraint left to reject it.
    assert_rejected(
        &prover,
        &mut rng,
        &honest,
        &WrapCircuit { wrap: true },
        "non-canonical (+r) truncation",
    );
}

// Pins the *production* binding structurally, without a proving round-trip: it
// fails the moment the real gadget stops wiring its inputs into a gate. The
// forge tests above catch the same regression — they attach their own copy of
// `bind_logic_accumulators`, so dropping the production call makes the honest
// circuit shrink and `assert_rejected`'s layout comparison fire — but this one
// says so directly and in a fraction of the time.
#[test]
fn append_logic_xor_wires_its_inputs() {
    const BIT_PAIRS: usize = 125; // 250-bit truncation, the Poseidon width

    let mut composer = Composer::initialized();
    let a = composer.append_witness(BlsScalar::from(0x0f0f_0ff0_u64));
    let b = composer.append_witness(BlsScalar::from(0xffff_0000_u64));

    let _ = composer.append_logic_xor::<BIT_PAIRS>(a, b);

    let mut a_wired = false;
    let mut b_wired = false;
    for gate in &composer.constraints {
        for wire in [gate.a, gate.b, gate.c, gate.d] {
            a_wired |= wire.index() == a.index();
            b_wired |= wire.index() == b.index();
        }
    }

    assert!(
        a_wired,
        "append_logic_xor must wire input `a` into a gate (output binding)",
    );
    assert!(
        b_wired,
        "append_logic_xor must wire input `b` into a gate (output binding)",
    );
}
