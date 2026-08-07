// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Fixed-base scalar multiplication: the signed-digit widget behind
//! `component_mul_generator`, its width bounds, and the canonicality check on
//! the input scalar.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};

use super::{
    Composer, Constraint, TorsionFreeWitnessPoint, Witness, WitnessPoint,
    constraint_system,
};
use crate::error::Error;

/// Bit width of a canonical Jubjub scalar.
pub(super) const JUBJUB_SCALAR_BITS: usize = 252;

/// Number of signed-digit rows emitted by the fixed-base scalar-multiplication
/// widget.
pub(super) const FIXED_BASE_SIGNED_DIGIT_ROUNDS: usize = 256;

/// A width-2 NAF of a 252-bit scalar may carry into bit 252, so 253 signed
/// digits are required. The remaining three most-significant rows must encode
/// zero.
pub(super) const FIXED_BASE_LEADING_ZERO_ROUNDS: usize =
    FIXED_BASE_SIGNED_DIGIT_ROUNDS - (JUBJUB_SCALAR_BITS + 1);

/// Widest effective signed-digit width at which the fixed-base accumulator
/// endpoint cannot encode a modulus wrap: `2^254 - 1 < q - (r - 1)`, verified
/// against the actual moduli by the width-bound test in
/// `tests::soundness::fixed_base`. Specific to the `(q, r)` pair — unrelated to
/// the 254-bit caps of the logic and truncation gadgets, which derive from
/// `q < 2^255` alone.
pub(super) const FIXED_BASE_MAX_SOUND_WIDTH: usize = 254;

// The leading rounds forced to zero cap the effective signed-digit width of
// `component_mul_generator`. At the width above or below, the accumulator
// endpoint cannot reach the claimed Jubjub scalar plus or minus the BLS
// scalar modulus, so the closing check is an integer equality rather than an
// equality modulo the BLS scalar field, ruling out modulus-wrap forgeries.
// One bit more and the forgery would compile clean, so an incompatible width
// change must fail the build.
const _: () = assert!(
    FIXED_BASE_SIGNED_DIGIT_ROUNDS - FIXED_BASE_LEADING_ZERO_ROUNDS
        <= FIXED_BASE_MAX_SOUND_WIDTH,
    "the fixed-base signed-digit width must stay too narrow to encode a modulus wrap"
);

// The zero-pin on `leading_accumulator` forces the top digits to zero as
// integers only while the leading block itself cannot wrap: `2^L - 1 < q`.
// `L <= FIXED_BASE_MAX_SOUND_WIDTH` suffices, since the width-bound test
// proves `2^254 - 1 < q - (r - 1) < q`. The cap is sufficient, not tight —
// the leading count sits far below it.
const _: () = assert!(
    FIXED_BASE_LEADING_ZERO_ROUNDS <= FIXED_BASE_MAX_SOUND_WIDTH,
    "the fixed-base leading-zero block must stay too narrow to wrap the BLS modulus"
);

/// Fixed-base scalar-multiplication gadgets
impl Composer {
    /// Evaluate `jubjub · generator` as a [`TorsionFreeWitnessPoint`].
    ///
    /// `generator` is appended to the circuit description as a constant. It
    /// is validated to be an on-curve point of exact prime order, so every
    /// multiple of it lies in the prime-order subgroup and the result carries
    /// the [`TorsionFreeWitnessPoint`] membership by construction; see that
    /// type for the boundary rule.
    ///
    /// The circuit constrains `jubjub` to the canonical Jubjub scalar interval
    /// `[0, r)`, where `r` is the prime-order subgroup modulus. It also bounds
    /// the signed-digit recurrence to 253 effective digits. Together these
    /// constraints make the closing equality an integer equality rather than
    /// merely an equality modulo the BLS scalar-field modulus `q`: the signed
    /// integer has absolute value below `2^253`, the input is below `2^252`,
    /// and therefore their difference has absolute value below `2^254 < q`.
    ///
    /// Without both bounds, a malicious prover could encode `q` in the 256
    /// signed digits. The scalar accumulator would then close at public zero
    /// in the BLS field while the point accumulator closes at the generally
    /// nonidentity point `[q]generator`.
    ///
    /// The three leading zero rows are retained because the fixed-base widget
    /// uses shifted wires between consecutive rows. This preserves its
    /// 256-row shifted-wire structure while constraining it to the 253 digits
    /// needed by a width-2 NAF of any canonical Jubjub scalar, including the
    /// carry for `r - 1`.
    ///
    /// # Circuit compatibility
    ///
    /// The added constraints change the circuit shape. Circuit-specific
    /// proving and verifier keys, and cached compressed circuit descriptions,
    /// must be regenerated. They add 70 gates per call, so the universal SRS
    /// does not need regeneration but the supplied parameters must have
    /// capacity for the larger circuit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::JubJubGeneratorNotPrimeOrder`] if `generator` is not
    /// an on-curve point of exact prime order. In particular, the identity,
    /// small-order points, and points with a nontrivial torsion component are
    /// rejected.
    ///
    /// Returns [`Error::JubJubScalarMalformed`] during honest witness
    /// generation if `jubjub` is not a canonical Jubjub scalar. Soundness does
    /// not rely on that host-side check: the same canonicality and signed-digit
    /// bounds are enforced by circuit constraints.
    pub fn component_mul_generator<P: Into<JubJubExtended>>(
        &mut self,
        jubjub: Witness,
        generator: P,
    ) -> Result<TorsionFreeWitnessPoint, Error> {
        let generator = generator.into();

        // Check Z first: is_on_curve converts to affine and panics on Z = 0.
        if generator.get_z() == BlsScalar::zero()
            || !bool::from(generator.is_on_curve())
            || !bool::from(generator.is_prime_order())
        {
            return Err(Error::JubJubGeneratorNotPrimeOrder);
        }

        // Reject malformed values during honest witness generation instead of
        // panicking or producing an invalid proof. This is only an API guard;
        // `append_fixed_base_signed_digits` enforces canonicality in-circuit.
        let scalar: JubJubScalar =
            match JubJubScalar::from_bytes(&self[jubjub].to_bytes()).into() {
                Some(s) => s,
                None => return Err(Error::JubJubScalarMalformed),
            };

        let width = 2;
        let wnaf_entries = scalar.compute_windowed_naf(width);

        debug_assert_eq!(
            wnaf_entries.len(),
            FIXED_BASE_SIGNED_DIGIT_ROUNDS,
            "the wnaf_entries array is expected to be 256 elements long"
        );

        // The generator passed the exact prime-order validation above, so
        // its multiples cannot leave the prime-order subgroup.
        self.append_fixed_base_signed_digits(jubjub, generator, &wnaf_entries)
            .map(TorsionFreeWitnessPoint::new_unchecked)
    }

    /// Constrain a fixed-base multiplication for a supplied signed-digit
    /// witness assignment.
    ///
    /// Split from honest wNAF generation, and reachable from the `composer`
    /// subtree for its unit tests. The constraints, not the provenance of
    /// `signed_digits`, must reject noncanonical and field-wrapping
    /// representations.
    pub(super) fn append_fixed_base_signed_digits(
        &mut self,
        jubjub: Witness,
        generator: JubJubExtended,
        signed_digits: &[i8; FIXED_BASE_SIGNED_DIGIT_ROUNDS],
    ) -> Result<WitnessPoint, Error> {
        self.assert_canonical_jubjub_scalar(jubjub);

        // Compute [2^i]generator and reverse the table to match the
        // most-significant-first Horner recurrence of the scalar accumulator.
        let mut wnaf_point_multiples: Vec<_> = {
            let mut multiples =
                vec![JubJubExtended::default(); FIXED_BASE_SIGNED_DIGIT_ROUNDS];

            multiples[0] = generator;

            for i in 1..FIXED_BASE_SIGNED_DIGIT_ROUNDS {
                multiples[i] = multiples[i - 1].double();
            }

            dusk_jubjub::batch_normalize(&mut multiples).collect()
        };

        wnaf_point_multiples.reverse();

        // initialize the accumulators
        let mut scalar_acc = vec![BlsScalar::zero()];
        let mut point_acc = vec![JubJubAffine::identity()];

        // Auxiliary point to help with checks on the backend.
        let two = BlsScalar::from(2u64);
        let xy_alphas: Vec<_> = signed_digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, entry)| {
                let (scalar_to_add, point_to_add) = match entry {
                    0 => (BlsScalar::zero(), JubJubAffine::identity()),
                    -1 => (BlsScalar::one().neg(), -wnaf_point_multiples[i]),
                    1 => (BlsScalar::one(), wnaf_point_multiples[i]),
                    _ => return Err(Error::UnsupportedWNAF2k),
                };

                let prev_accumulator = two * scalar_acc[i];
                let scalar = prev_accumulator + scalar_to_add;
                scalar_acc.push(scalar);

                let a = JubJubExtended::from(point_acc[i]);
                let b = JubJubExtended::from(point_to_add);
                let point = a + b;
                point_acc.push(point.into());

                let x_alpha = point_to_add.get_u();
                let y_alpha = point_to_add.get_v();

                Ok(x_alpha * y_alpha)
            })
            .collect::<Result<_, Error>>()?;

        let mut leading_accumulator = Self::ZERO;

        for i in 0..FIXED_BASE_SIGNED_DIGIT_ROUNDS {
            let acc_x = self.append_witness(point_acc[i].get_u());
            let acc_y = self.append_witness(point_acc[i].get_v());
            let accumulated_bit = self.append_witness(scalar_acc[i]);

            if i == FIXED_BASE_LEADING_ZERO_ROUNDS {
                leading_accumulator = accumulated_bit;
            }

            // the point accumulator must start from identity and its scalar
            // from zero
            if i == 0 {
                self.assert_equal_constant(acc_x, BlsScalar::zero(), None);
                self.assert_equal_constant(acc_y, BlsScalar::one(), None);
                self.assert_equal_constant(
                    accumulated_bit,
                    BlsScalar::zero(),
                    None,
                );
            }

            let x_beta = wnaf_point_multiples[i].get_u();
            let y_beta = wnaf_point_multiples[i].get_v();

            let xy_alpha = self.append_witness(xy_alphas[i]);
            let xy_beta = x_beta * y_beta;

            let wnaf_round = constraint_system::ecc::WnafRound {
                acc_x,
                acc_y,
                accumulated_bit,
                xy_alpha,
                x_beta,
                y_beta,
                xy_beta,
            };

            let constraint =
                Constraint::group_add_fixed_base(&Constraint::new())
                    .left(wnaf_round.x_beta)
                    .right(wnaf_round.y_beta)
                    .constant(wnaf_round.xy_beta)
                    .a(wnaf_round.acc_x)
                    .b(wnaf_round.acc_y)
                    .c(wnaf_round.xy_alpha)
                    .d(wnaf_round.accumulated_bit);

            self.append_custom_gate(constraint)
        }

        // This row is a shifted-wire anchor for the last fixed-base step.
        // The previous q_fixed_group_add row constrains these as a_w/b_w/d_w.
        let acc_x = self
            .append_witness(point_acc[FIXED_BASE_SIGNED_DIGIT_ROUNDS].get_u());
        let acc_y = self
            .append_witness(point_acc[FIXED_BASE_SIGNED_DIGIT_ROUNDS].get_v());

        // This is the final scalar recurrence state
        // It is constrained by the previous fixed-base row as d_w and by
        // assert_equal below
        let last_accumulated_bit =
            self.append_witness(scalar_acc[FIXED_BASE_SIGNED_DIGIT_ROUNDS]);

        // Keep this anchor row since removing it would break the shifted-wire
        // chain.
        let constraint =
            Constraint::new().a(acc_x).b(acc_y).d(last_accumulated_bit);
        self.append_gate(constraint);

        // The first three signed digits (bits 255, 254, and 253) must all be
        // zero. Starting from zero, their weighted sum lies in [-7, 7], so it
        // cannot wrap the BLS field; the only {-1, 0, 1} assignment with
        // accumulator zero after these rounds is (0, 0, 0). This leaves 253
        // effective digits, enough for the width-2 NAF carry of a 252-bit
        // Jubjub scalar but too few to encode ±q.
        self.assert_equal_constant(
            leading_accumulator,
            BlsScalar::zero(),
            None,
        );

        // constrain the last element in the accumulator to be equal to the
        // input jubjub scalar
        self.assert_equal(last_accumulated_bit, jubjub);

        Ok(WitnessPoint::new(acc_x, acc_y))
    }

    /// Constrain `scalar` to the canonical Jubjub scalar interval `[0, r)`.
    ///
    /// The first range check establishes `scalar < 2^252`. The second checks
    /// `(r - 1) - scalar < 2^252`; if `scalar >= r`, that subtraction
    /// underflows modulo the much larger BLS scalar-field modulus and cannot
    /// satisfy the range check.
    ///
    /// Reachable from the `composer` subtree for its unit tests.
    pub(super) fn assert_canonical_jubjub_scalar(&mut self, scalar: Witness) {
        self.range_check(scalar, JUBJUB_SCALAR_BITS);

        let max_jubjub_scalar = BlsScalar::from(-JubJubScalar::one());
        let distance_from_max = self.gate_add(
            Constraint::new()
                .left(-BlsScalar::one())
                .a(scalar)
                .constant(max_jubjub_scalar),
        );
        self.range_check(distance_from_max, JUBJUB_SCALAR_BITS);
    }
}
