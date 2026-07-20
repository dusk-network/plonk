// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

mod common;
use common::{check_satisfied_circuit, check_unsatisfied_circuit};

// Truncates `input` to its low `N` bits and exposes the result as a public
// input. A satisfying assignment requires `claimed_low` to equal the honest
// truncation of `input`.
struct TruncCircuit<const N: usize> {
    input: BlsScalar,
    claimed_low: BlsScalar,
}

impl<const N: usize> Default for TruncCircuit<N> {
    // The default input value is arbitrary: the gate layout keys off the
    // compile-time `N` (the split widths are fixed by `N`, not by the value),
    // so any input compiles the same circuit description.
    fn default() -> Self {
        Self {
            input: -BlsScalar::one(),
            claimed_low: BlsScalar::zero(),
        }
    }
}

impl<const N: usize> Circuit for TruncCircuit<N> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let witness = composer.append_witness(self.input);
        let low = composer.component_truncate::<N>(witness);
        let pi = composer.append_public(self.claimed_low);
        composer.assert_equal(low, pi);

        Ok(())
    }
}

#[test]
fn truncate() {
    let mut rng = StdRng::seed_from_u64(0x7_b1eeb);
    let pp = PublicParameters::setup(1 << 12, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let label = b"component_truncate";

    // --- 8-bit truncation: exercises a non-zero high part with hand-computable
    // values. `0x1234` truncates to `0x34`. ---
    let (prover, verifier) = Compiler::compile::<TruncCircuit<8>>(&pp, label)
        .expect("Circuit should compile");

    let input = BlsScalar::from(0x1234u64);
    let low = BlsScalar::from(0x34u64);
    let pi = vec![low];
    let msg = "8-bit truncation of a wider input should verify";
    let circuit = TruncCircuit::<8> {
        input,
        claimed_low: low,
    };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // A claimed low that is not the truncation is unsatisfiable.
    let msg = "Wrong truncation claim should fail to prove";
    let circuit = TruncCircuit::<8> {
        input,
        claimed_low: BlsScalar::from(0x35u64),
    };
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);

    // --- 7-bit (odd) truncation: `0x1234` truncates to `0x34 & 0x7f = 0x34`;
    // `0x12B4` (low byte `0xB4`) truncates to `0xB4 & 0x7f = 0x34` too, so the
    // dropped 8th bit is genuinely exercised. ---
    let (prover, verifier) = Compiler::compile::<TruncCircuit<7>>(&pp, label)
        .expect("Circuit should compile");

    let input = BlsScalar::from(0x12B4u64);
    let low = BlsScalar::from(0x34u64); // 0xB4 mod 2^7
    let pi = vec![low];
    let msg = "Odd-width (7-bit) truncation should verify";
    let circuit = TruncCircuit::<7> {
        input,
        claimed_low: low,
    };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    let msg = "Wrong odd-width truncation claim should fail to prove";
    let circuit = TruncCircuit::<7> {
        input,
        claimed_low: BlsScalar::from(0xB4u64), // the untruncated low byte
    };
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);

    // --- 250-bit truncation: the Schnorr-challenge width. An input below
    // `2^250` is its own truncation (zero high part). ---
    let (prover, verifier) = Compiler::compile::<TruncCircuit<250>>(&pp, label)
        .expect("Circuit should compile");

    let input = BlsScalar::from(0x1_2345_6789_abcdu64);
    let pi = vec![input];
    let msg = "Sub-2^250 input truncates to itself and should verify";
    let circuit = TruncCircuit::<250> {
        input,
        claimed_low: input,
    };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    let msg = "Wrong truncation claim should fail to prove";
    let circuit = TruncCircuit::<250> {
        input,
        claimed_low: input + BlsScalar::one(),
    };
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);

    // --- N = 0: the lower boundary. The low part is the empty bit range, so
    // the truncation of any input is `0`. ---
    let (prover, verifier) = Compiler::compile::<TruncCircuit<0>>(&pp, label)
        .expect("Circuit should compile");

    let input = BlsScalar::from(0x1_2345_6789_abcdu64);
    let pi = vec![BlsScalar::zero()];
    let msg = "Truncation to 0 bits is always 0 and should verify";
    let circuit = TruncCircuit::<0> {
        input,
        claimed_low: BlsScalar::zero(),
    };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    let msg = "Non-zero claim for a 0-bit truncation should fail to prove";
    let circuit = TruncCircuit::<0> {
        input,
        claimed_low: BlsScalar::one(),
    };
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);

    // --- N = 254: the upper boundary (the compile-time cap and the only width
    // where the canonical guard's `r_high` is 1). An input below `2^254` is its
    // own truncation. ---
    let (prover, verifier) = Compiler::compile::<TruncCircuit<254>>(&pp, label)
        .expect("Circuit should compile");

    let input = BlsScalar::from(0x1_2345_6789_abcdu64);
    let pi = vec![input];
    let msg = "Sub-2^254 input truncates to itself and should verify";
    let circuit = TruncCircuit::<254> {
        input,
        claimed_low: input,
    };
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    let msg = "Wrong 254-bit truncation claim should fail to prove";
    let circuit = TruncCircuit::<254> {
        input,
        claimed_low: input + BlsScalar::one(),
    };
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);
}
