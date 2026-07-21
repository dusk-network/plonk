// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! PLONK turbo composer definitions

use alloc::vec::Vec;
use core::{cmp, ops};

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use hashbrown::HashMap;

use crate::bit_iterator::BitIterator8;
use crate::error::Error;
use crate::runtime::{Runtime, RuntimeEvent};

mod circuit;
mod compress;
mod constraint_system;
mod gate;

#[cfg(test)]
mod logic_gate_soundness_tests;

#[cfg(test)]
mod range_soundness_tests;

#[cfg(test)]
mod soundness_support;

#[cfg(test)]
mod truncate_soundness_tests;

pub(crate) mod permutation;

pub use circuit::Circuit;
pub use constraint_system::{Constraint, Witness, WitnessPoint};
pub(crate) use constraint_system::{Selector, WireData, WiredWitness};
pub use gate::Gate;
pub(crate) use permutation::Permutation;

/// Construct and prove circuits
#[derive(Debug, Clone)]
pub struct Composer {
    /// Constraint system gates
    pub(crate) constraints: Vec<Gate>,

    /// Sparse representation of the public inputs
    pub(crate) public_inputs: HashMap<usize, BlsScalar>,

    /// Witness values
    pub(crate) witnesses: Vec<BlsScalar>,

    /// Permutation argument.
    pub(crate) perm: Permutation,

    /// PLONK runtime controller
    pub(crate) runtime: Runtime,
}

impl ops::Index<Witness> for Composer {
    type Output = BlsScalar;

    fn index(&self, w: Witness) -> &Self::Output {
        &self.witnesses[w.index()]
    }
}

/// Recompose `bits[start..end]` (little-endian, bit `i` weighing `2^i`) into a
/// field element with `bits[start]` as the least significant bit, i.e. the
/// value `sum_{i in [start, end)} bits[i] * 2^(i - start)`.
fn recompose_bits(bits: &[u8; 256], start: usize, end: usize) -> BlsScalar {
    let two = BlsScalar::from(2u64);
    let mut value = BlsScalar::zero();
    for i in (start..end).rev() {
        value *= two;
        if bits[i] == 1 {
            value += BlsScalar::one();
        }
    }
    value
}

// pub trait Composer: Sized + Index<Witness, Output = BlsScalar> {
/// Circuit builder tool
impl Composer {
    /// Identity point representation inside the constraint system
    pub const IDENTITY: WitnessPoint = WitnessPoint::new(Self::ZERO, Self::ONE);
    /// `One` representation inside the constraint system.
    ///
    /// A turbo composer expects the 2nd witness to be always present and to
    /// be one.
    pub const ONE: Witness = Witness::ONE;
    /// Zero representation inside the constraint system.
    ///
    /// A turbo composer expects the first witness to be always present and to
    /// be zero.
    pub const ZERO: Witness = Witness::ZERO;

    /// Constraints count
    pub fn constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Create a [`Composer`] instance from a compressed circuit
    pub(crate) fn from_bytes(compressed: &[u8]) -> Result<Self, Error> {
        compress::CompressedCircuit::from_bytes(compressed)
    }

    /// Allocate a witness value into the composer and return its index.
    fn append_witness_internal(&mut self, witness: BlsScalar) -> Witness {
        let n = self.witnesses.len();

        // Get a new Witness from the permutation
        self.perm.new_witness();

        // Bind the allocated witness
        self.witnesses.push(witness);

        Witness::new(n)
    }

    /// Append a new width-4 gate/constraint.
    fn append_custom_gate_internal(&mut self, constraint: Constraint) {
        let n = self.constraints.len();

        let a = constraint.witness(WiredWitness::A);
        let b = constraint.witness(WiredWitness::B);
        let c = constraint.witness(WiredWitness::C);
        let d = constraint.witness(WiredWitness::D);

        let q_m = *constraint.coeff(Selector::Multiplication);
        let q_l = *constraint.coeff(Selector::Left);
        let q_r = *constraint.coeff(Selector::Right);
        let q_o = *constraint.coeff(Selector::Output);
        let q_f = *constraint.coeff(Selector::Fourth);
        let q_c = *constraint.coeff(Selector::Constant);

        let q_arith = *constraint.coeff(Selector::Arithmetic);
        let q_range = *constraint.coeff(Selector::Range);
        let q_logic = *constraint.coeff(Selector::Logic);
        let q_fixed_group_add = *constraint.coeff(Selector::GroupAddFixedBase);
        let q_variable_group_add =
            *constraint.coeff(Selector::GroupAddVariableBase);

        let gate = Gate {
            q_m,
            q_l,
            q_r,
            q_o,
            q_f,
            q_c,
            q_arith,
            q_range,
            q_logic,
            q_fixed_group_add,
            q_variable_group_add,
            a,
            b,
            c,
            d,
        };

        self.constraints.push(gate);

        if constraint.has_public_input() {
            let pi = *constraint.coeff(Selector::PublicInput);

            self.public_inputs.insert(n, pi);
        }

        self.perm.add_witnesses_to_map(a, b, c, d, n);
    }

    /// PLONK runtime controller
    pub(crate) fn runtime(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

    /// Initialize the constraint system with the constants for 0 and 1 and
    /// append two dummy gates
    pub fn initialized() -> Self {
        let mut slf = Self::uninitialized();

        let zero = slf.append_witness(0);
        let one = slf.append_witness(1);

        slf.assert_equal_constant(zero, 0, None);
        slf.assert_equal_constant(one, 1, None);

        slf.append_dummy_gates();

        slf
    }

    /// Create an empty constraint system.
    ///
    /// This shouldn't be used directly; instead, use [`Self::initialized`]
    pub(crate) fn uninitialized() -> Self {
        Self {
            constraints: Vec::new(),
            public_inputs: HashMap::new(),
            witnesses: Vec::new(),
            perm: Permutation::new(),
            runtime: Runtime::new(),
        }
    }

    /// Adds blinding factors to the witness polynomials with two dummy
    /// arithmetic constraints
    fn append_dummy_gates(&mut self) {
        let six = self.append_witness(BlsScalar::from(6));
        let one = self.append_witness(BlsScalar::from(1));
        let seven = self.append_witness(BlsScalar::from(7));
        let min_twenty = self.append_witness(-BlsScalar::from(20));

        // Add a dummy constraint so that we do not have zero polynomials
        let constraint = Constraint::new()
            .mult(1)
            .left(2)
            .right(3)
            .fourth(1)
            .constant(4)
            .output(4)
            .a(six)
            .b(seven)
            .d(one)
            .c(min_twenty);

        self.append_gate(constraint);

        // Add another dummy constraint so that we do not get the identity
        // permutation
        let constraint = Constraint::new()
            .mult(1)
            .left(1)
            .right(1)
            .constant(127)
            .output(1)
            .a(min_twenty)
            .b(six)
            .c(seven);

        self.append_gate(constraint);
    }

    /// Allocate a witness value into the composer and return its index.
    pub fn append_witness<W: Into<BlsScalar>>(
        &mut self,
        witness: W,
    ) -> Witness {
        let witness = witness.into();

        let witness = self.append_witness_internal(witness);

        #[cfg(feature = "debug")]
        let v = self[witness];
        self.runtime().event(RuntimeEvent::WitnessAppended {
            #[cfg(feature = "debug")]
            w: witness,
            #[cfg(feature = "debug")]
            v,
        });

        witness
    }

    /// Append a new width-4 gate/constraint.
    pub fn append_custom_gate(&mut self, constraint: Constraint) {
        self.runtime().event(RuntimeEvent::ConstraintAppended {
            #[cfg(feature = "debug")]
            c: constraint,
        });

        self.append_custom_gate_internal(constraint)
    }

    /// Performs a logical AND or XOR op between the inputs provided for
    /// `num_bits = BIT_PAIRS * 2` bits (counting from the least significant).
    ///
    /// `BIT_PAIRS` is capped at `127` (254 bits): the closing truncation
    /// binding is only canonical up to 254 bits, since a canonical
    /// `BlsScalar` is 255 bits. `BIT_PAIRS > 127` would silently drop input
    /// bits, so it is rejected at **compile time** rather than truncated.
    ///
    /// Each logic op adds `BIT_PAIRS + 1` gates for the operation itself, plus
    /// the gates binding the result to the input witnesses. Per input the
    /// binding range-checks the high part and the canonical guard's two
    /// differences — a total width of `510 - num_bits` bits, so roughly
    /// `(510 - num_bits) / 8` gates plus a small fixed remainder. The binding
    /// therefore shrinks as `num_bits` grows, but the operation loop grows
    /// twice as fast, so the total rises with width: 172 gates at 2 bits, 234
    /// at 250.
    ///
    /// ## Constraint
    /// - is_component_xor = 1 -> Performs XOR between the first `num_bits` for
    ///   `a` and `b`.
    /// - is_component_xor = 0 -> Performs AND between the first `num_bits` for
    ///   `a` and `b`.
    pub fn append_logic_component<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
        is_component_xor: bool,
    ) -> Witness {
        // The bits are processed in quads (two bits each), so the width is
        // always even. It is capped at 254 — the largest even width for which
        // the closing truncation binding below is canonical (a canonical
        // `BlsScalar` is 255 bits). Exceeding `BIT_PAIRS = 127` would silently
        // drop bits, a soundness footgun, so it is a hard compile-time error
        // rather than a quiet cap.
        const {
            assert!(
                BIT_PAIRS <= 127,
                "BIT_PAIRS must be <= 127: the logic gadget operates on at most 254 bits"
            )
        };

        let num_bits = BIT_PAIRS * 2;
        let num_quads = BIT_PAIRS;

        let bls_four = BlsScalar::from(4u64);
        let mut left_acc = BlsScalar::zero();
        let mut right_acc = BlsScalar::zero();
        let mut out_acc = BlsScalar::zero();

        // skip bits outside of argument `num_bits`
        let a_bit_iter = BitIterator8::new(self[a].to_bytes());
        let a_bits: Vec<_> = a_bit_iter.skip(256 - num_bits).collect();
        let b_bit_iter = BitIterator8::new(self[b].to_bytes());
        let b_bits: Vec<_> = b_bit_iter.skip(256 - num_bits).collect();

        //
        // * +-----+-----+-----+-----+
        // * |  A  |  B  |  C  |  D  |
        // * +-----+-----+-----+-----+
        // * | 0   | 0   | w1  | 0   |
        // * | a1  | b1  | w2  | d1  |
        // * | a2  | b2  | w3  | d2  |
        // * |  :  |  :  |  :  |  :  |
        // * | an  | bn  | 0   | dn  |
        // * +-----+-----+-----+-----+
        // `an`, `bn` and `dn` are accumulators: `an [& OR ^] bd = dn`
        //
        // each step will shift last computation two bits to the left and add
        // current quad.
        //
        // `wn` product accumulators will safeguard the quotient polynomial.

        let mut constraint = if is_component_xor {
            Constraint::logic_xor(&Constraint::new())
        } else {
            Constraint::logic(&Constraint::new())
        };

        for i in 0..num_quads {
            // commit every accumulator
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

            // `w` argument to safeguard the quotient polynomial
            let prod_quad_bls = (left_quad * right_quad) as u64;
            let prod_quad_bls = BlsScalar::from(prod_quad_bls);

            // Now that we've computed this round results, we need to apply the
            // logic transition constraint that will check that
            //   a_{i+1} - (a_i << 2) < 4
            //   b_{i+1} - (b_i << 2) < 4
            //   d_{i+1} - (d_i << 2) < 4   with d_i = a_i [& OR ^] b_i
            // Note that multiplying by four is the equivalent of shifting the
            // bits two positions to the left.

            left_acc = left_acc * bls_four + left_quad_bls;
            right_acc = right_acc * bls_four + right_quad_bls;
            out_acc = out_acc * bls_four + out_quad_bls;

            let wit_a = self.append_witness(left_acc);
            let wit_b = self.append_witness(right_acc);
            let wit_c = self.append_witness(prod_quad_bls);
            let wit_d = self.append_witness(out_acc);

            constraint = constraint.c(wit_c);

            self.append_custom_gate(constraint);

            constraint = constraint.a(wit_a).b(wit_b).d(wit_d);
        }

        // pad last output with `0`
        // | an  | bn  | 0   | dn  |
        let left_acc_wit = constraint.witness(WiredWitness::A);
        let right_acc_wit = constraint.witness(WiredWitness::B);
        let d = constraint.witness(WiredWitness::D);

        let constraint =
            Constraint::new().a(left_acc_wit).b(right_acc_wit).d(d);

        self.append_custom_gate(constraint);

        // Bind the recomposed accumulators to the input witnesses. The loop
        // above constrains the accumulators only among themselves;
        // without this binding the output is decoupled from `a`/`b` and
        // a malicious prover can pick arbitrary accumulators (and thus
        // an arbitrary output) for the identical gate layout. Mirrors
        // `component_range`'s closing `assert_equal`, generalised to a
        // canonical truncation to `num_bits` bits.
        self.bind_logic_accumulators::<BIT_PAIRS>(
            a,
            b,
            left_acc_wit,
            right_acc_wit,
        );

        d
    }

    /// Bind the recomposed logic accumulators to the gadget's input witnesses.
    ///
    /// `left_acc`/`right_acc` are the final accumulators produced by
    /// [`Self::append_logic_component`]; the logic gate guarantees each lies in
    /// `[0, 2^num_bits)`. This binds them to the low `num_bits` of `a`/`b` so
    /// the output cannot be decoupled from the inputs.
    fn bind_logic_accumulators<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
        left_acc: Witness,
        right_acc: Witness,
    ) {
        // A zero-bit logic op reads no input bits and returns `0`, so there is
        // nothing to bind.
        if BIT_PAIRS == 0 {
            return;
        }

        self.bind_truncated_input::<BIT_PAIRS>(a, left_acc);
        self.bind_truncated_input::<BIT_PAIRS>(b, right_acc);
    }

    /// Constrain `acc` to be the low `num_bits = BIT_PAIRS * 2` bits of
    /// `input` (`BIT_PAIRS <= 127`, enforced by the caller).
    ///
    /// `acc` is already constrained to `[0, 2^num_bits)` by the logic gate;
    /// this ties it to `input` through the shared truncation split.
    fn bind_truncated_input<const BIT_PAIRS: usize>(
        &mut self,
        input: Witness,
        acc: Witness,
    ) {
        // matches the width of `append_logic_component`, which caps
        // `BIT_PAIRS` at 127 (254 bits) at compile time
        let num_bits = BIT_PAIRS * 2;
        self.bind_truncation_split(input, acc, num_bits);
    }

    /// Bind an already-bounded `low` to the low `num_bits` of `input` via the
    /// canonical truncation split `input = high * 2^num_bits + low`.
    ///
    /// Derives `high` from `input`, range-checks it to
    /// `[0, 2^(255 - num_bits))`, enforces the linear relation, and adds the
    /// canonical `< r` guard so the split cannot alias `input + r`. The caller
    /// MUST already constrain `low` to `[0, 2^num_bits)` — with a range check,
    /// or through the logic gate for the logic gadget — otherwise the split is
    /// not unique and the binding is unsound. Shared core of
    /// [`Self::component_truncate`] and [`Self::bind_truncated_input`].
    fn bind_truncation_split(
        &mut self,
        input: Witness,
        low: Witness,
        num_bits: usize,
    ) {
        // A canonical field element is < 2^255, so its high part fits in
        // `255 - num_bits` bits.
        let high_bits = 255 - num_bits;
        let pow = BlsScalar::pow_of_2(num_bits as u64);

        // high = floor(input / 2^num_bits), recomposed from the high input
        // bits, range-checked so it cannot absorb a different low part.
        let input_bits = self[input].to_bits();
        let high_value = recompose_bits(&input_bits, num_bits, 256);
        let high = self.append_witness(high_value);
        self.range_check(high, high_bits);

        // input == high * 2^num_bits + low
        let recomposed =
            self.gate_add(Constraint::new().left(pow).right(1).a(high).b(low));
        self.assert_equal(recomposed, input);

        // The linear relation above also admits the non-canonical assignment
        // that recomposes to `input + r` (a small `high` with a different
        // `low`, both still in range), decoupling `low` from `input`. The
        // canonical guard rejects exactly that alias, pinning `low` to the
        // integer reduction.
        self.assert_canonical_truncation(high, low, num_bits);
    }

    /// Evaluate `jubjub · Generator` as a [`WitnessPoint`]
    ///
    /// `generator` will be appended to the circuit description as constant
    ///
    /// Will error with a `JubJubScalarMalformed` error if `jubjub` doesn't fit
    /// `Fr`
    pub fn component_mul_generator<P: Into<JubJubExtended>>(
        &mut self,
        jubjub: Witness,
        generator: P,
    ) -> Result<WitnessPoint, Error> {
        let generator = generator.into();

        // the number of bits is truncated to the maximum possible. however, we
        // could slice off 3 bits from the top of wnaf since Fr price is
        // 252 bits. Alternatively, we could move to base4 and halve the
        // number of gates considering that the product of wnaf adjacent
        // entries is zero.
        let bits: usize = 256;

        // compute 2^iG
        let mut wnaf_point_multiples: Vec<_> = {
            let mut multiples = vec![JubJubExtended::default(); bits];

            multiples[0] = generator;

            for i in 1..bits {
                multiples[i] = multiples[i - 1].double();
            }

            dusk_jubjub::batch_normalize(&mut multiples).collect()
        };

        wnaf_point_multiples.reverse();

        // we should error instead of producing invalid proofs - otherwise this
        // can easily become an attack vector to either shutdown prover
        // services or create malicious statements
        let scalar: JubJubScalar =
            match JubJubScalar::from_bytes(&self[jubjub].to_bytes()).into() {
                Some(s) => s,
                None => return Err(Error::JubJubScalarMalformed),
            };

        let width = 2;
        let wnaf_entries = scalar.compute_windowed_naf(width);

        // this will pass as long as `compute_windowed_naf` returns an array
        // with 256 elements
        debug_assert_eq!(
            wnaf_entries.len(),
            bits,
            "the wnaf_entries array is expected to be 256 elements long"
        );

        // initialize the accumulators
        let mut scalar_acc = vec![BlsScalar::zero()];
        let mut point_acc = vec![JubJubAffine::identity()];

        // auxillary point to help with checks on the backend
        let two = BlsScalar::from(2u64);
        let xy_alphas: Vec<_> = wnaf_entries
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

        for i in 0..bits {
            let acc_x = self.append_witness(point_acc[i].get_u());
            let acc_y = self.append_witness(point_acc[i].get_v());
            let accumulated_bit = self.append_witness(scalar_acc[i]);

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
        let acc_x = self.append_witness(point_acc[bits].get_u());
        let acc_y = self.append_witness(point_acc[bits].get_v());

        // This is the final scalar recurrence state
        // It is constrained by the previous fixed-base row as d_w and by
        // assert_equal below
        let last_accumulated_bit = self.append_witness(scalar_acc[bits]);

        // Keep this anchor row since removing it would break the shifted-wire
        // chain.
        let constraint =
            Constraint::new().a(acc_x).b(acc_y).d(last_accumulated_bit);
        self.append_gate(constraint);

        // constrain the last element in the accumulator to be equal to the
        // input jubjub scalar
        self.assert_equal(last_accumulated_bit, jubjub);

        Ok(WitnessPoint::new(acc_x, acc_y))
    }

    /// Append a new width-4 gate/constraint.
    ///
    /// The constraint added will enforce the following:
    /// `q_M · a · b  + q_L · a + q_R · b + q_O · o + q_F · d + q_C + PI = 0`.
    pub fn append_gate(&mut self, constraint: Constraint) {
        let constraint = Constraint::arithmetic(&constraint);

        self.append_custom_gate(constraint)
    }

    /// Evaluate the polynomial and append an output that satisfies the equation
    ///
    /// Return `None` if the output selector is zero
    pub fn append_evaluated_output(
        &mut self,
        s: Constraint,
    ) -> Option<Witness> {
        let a = s.witness(WiredWitness::A);
        let b = s.witness(WiredWitness::B);
        let d = s.witness(WiredWitness::D);

        let a = self[a];
        let b = self[b];
        let d = self[d];

        let qm = s.coeff(Selector::Multiplication);
        let ql = s.coeff(Selector::Left);
        let qr = s.coeff(Selector::Right);
        let qf = s.coeff(Selector::Fourth);
        let qc = s.coeff(Selector::Constant);
        let pi = s.coeff(Selector::PublicInput);

        let x = qm * a * b + ql * a + qr * b + qf * d + qc + pi;

        let y = s.coeff(Selector::Output);

        // Invert is an expensive operation; in most cases, `q_O` is going to be
        // either 1 or -1, so we can optimize these
        #[allow(dead_code)]
        let c = {
            const ONE: BlsScalar = BlsScalar::one();
            const MINUS_ONE: BlsScalar = BlsScalar([
                0xfffffffd00000003,
                0xfb38ec08fffb13fc,
                0x99ad88181ce5880f,
                0x5bc8f5f97cd877d8,
            ]);

            // Can't use a match pattern here since `BlsScalar` doesn't derive
            // `PartialEq`
            if y == &ONE {
                Some(-x)
            } else if y == &MINUS_ONE {
                Some(x)
            } else {
                y.invert().map(|y| x * (-y))
            }
        };

        c.map(|c| self.append_witness(c))
    }

    /// Constrain a scalar into the circuit description and return an allocated
    /// [`Witness`] with its value
    pub fn append_constant<C: Into<BlsScalar>>(
        &mut self,
        constant: C,
    ) -> Witness {
        let constant = constant.into();
        let witness = self.append_witness(constant);

        self.assert_equal_constant(witness, constant, None);

        witness
    }

    /// Appends a point in affine form as [`WitnessPoint`]
    pub fn append_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();

        let x = self.append_witness(affine.get_u());
        let y = self.append_witness(affine.get_v());

        WitnessPoint::new(x, y)
    }

    /// Constrain a point into the circuit description and return an allocated
    /// [`WitnessPoint`] with its coordinates
    pub fn append_constant_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();

        let x = self.append_constant(affine.get_u());
        let y = self.append_constant(affine.get_v());

        WitnessPoint::new(x, y)
    }

    /// Appends a point in affine form as [`WitnessPoint`]
    ///
    /// Creates two public inputs as `(x, y)`
    pub fn append_public_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();
        let point = self.append_point(affine);

        self.assert_equal_constant(
            *point.x(),
            BlsScalar::zero(),
            Some(affine.get_u()),
        );

        self.assert_equal_constant(
            *point.y(),
            BlsScalar::zero(),
            Some(affine.get_v()),
        );

        point
    }

    /// Allocate a witness value into the composer and return its index.
    ///
    /// Create a public input with the scalar
    pub fn append_public<P: Into<BlsScalar>>(&mut self, public: P) -> Witness {
        let public = public.into();
        let witness = self.append_witness(public);

        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(witness)
            .public(public);
        self.append_gate(constraint);

        witness
    }

    /// Asserts `a == b` by appending a gate
    pub fn assert_equal(&mut self, a: Witness, b: Witness) {
        let constraint =
            Constraint::new().left(1).right(-BlsScalar::one()).a(a).b(b);

        self.append_gate(constraint);
    }

    /// Adds a logical AND gate that performs the bitwise AND between two
    /// values for the specified first `num_bits = BIT_PAIRS * 2` bits
    /// (`BIT_PAIRS <= 127`, max 254 bits) returning a [`Witness`] holding the
    /// result.
    pub fn append_logic_and<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
    ) -> Witness {
        self.append_logic_component::<BIT_PAIRS>(a, b, false)
    }

    /// Adds a logical XOR gate that performs the XOR between two values for
    /// the specified first `num_bits = BIT_PAIRS * 2` bits (`BIT_PAIRS <=
    /// 127`, max 254 bits) returning a [`Witness`] holding the result.
    pub fn append_logic_xor<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
    ) -> Witness {
        self.append_logic_component::<BIT_PAIRS>(a, b, true)
    }

    /// Constrain `a` to be equal to `constant + pi`.
    ///
    /// `constant` will be defined as part of the public circuit description.
    pub fn assert_equal_constant<C: Into<BlsScalar>>(
        &mut self,
        a: Witness,
        constant: C,
        public: Option<BlsScalar>,
    ) {
        let constant = constant.into();
        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(a)
            .constant(constant);
        let constraint =
            public.map(|p| constraint.public(p)).unwrap_or(constraint);

        self.append_gate(constraint);
    }

    /// Asserts that the coordinates of the two points `a` and `b` are the same
    /// by appending two gates
    pub fn assert_equal_point(&mut self, a: WitnessPoint, b: WitnessPoint) {
        self.assert_equal(*a.x(), *b.x());
        self.assert_equal(*a.y(), *b.y());
    }

    /// Asserts `point == public`.
    ///
    /// Will add `public` affine coordinates `(x,y)` as public inputs
    pub fn assert_equal_public_point<P: Into<JubJubAffine>>(
        &mut self,
        point: WitnessPoint,
        public: P,
    ) {
        let public = public.into();

        self.assert_equal_constant(
            *point.x(),
            BlsScalar::zero(),
            Some(public.get_u()),
        );

        self.assert_equal_constant(
            *point.y(),
            BlsScalar::zero(),
            Some(public.get_v()),
        );
    }

    /// Negates a curve point by consuming 1 gate.
    pub fn component_neg_point(&mut self, p: WitnessPoint) -> WitnessPoint {
        // We negate the 'x' coordinate of the point 'p', so that
        // neg_point = (-p.x, p.y)
        let constraint = Constraint::new().left(-BlsScalar::one()).a(*p.x());
        let neg_p_x = self.gate_mul(constraint);

        WitnessPoint::new(neg_p_x, *p.y())
    }

    /// Subtracts a curve point from another by consuming 3 gates.
    pub fn component_sub_point(
        &mut self,
        a: WitnessPoint,
        b: WitnessPoint,
    ) -> WitnessPoint {
        // We negate the point 'b'
        let neg_b = self.component_neg_point(b);

        // We return a + (-b)
        self.component_add_point(a, neg_b)
    }

    /// Adds two curve points by consuming 2 gates.
    pub fn component_add_point(
        &mut self,
        a: WitnessPoint,
        b: WitnessPoint,
    ) -> WitnessPoint {
        // In order to verify that two points were correctly added
        // without going over a degree 4 polynomial, we will need
        // x_1, y_1, x_2, y_2
        // x_3, y_3, x_1 * y_2

        let x_1 = *a.x();
        let y_1 = *a.y();
        let x_2 = *b.x();
        let y_2 = *b.y();

        let p1 = JubJubAffine::from_raw_unchecked(self[x_1], self[y_1]);
        let p2 = JubJubAffine::from_raw_unchecked(self[x_2], self[y_2]);

        let point: JubJubAffine = (JubJubExtended::from(p1) + p2).into();

        let x_3 = point.get_u();
        let y_3 = point.get_v();

        let x1_y2 = self[x_1] * self[y_2];

        let x_1_y_2 = self.append_witness(x1_y2);
        let x_3 = self.append_witness(x_3);
        let y_3 = self.append_witness(y_3);

        // Add the rest of the prepared points into the composer
        let constraint = Constraint::new().a(x_1).b(y_1).c(x_2).d(y_2);
        let constraint = Constraint::group_add_variable_base(&constraint);

        self.append_custom_gate(constraint);

        let constraint = Constraint::new().a(x_3).b(y_3).d(x_1_y_2);

        self.append_custom_gate(constraint);

        WitnessPoint::new(x_3, y_3)
    }

    /// Adds a boolean constraint (also known as binary constraint) where the
    /// gate eq. will enforce that the [`Witness`] received is either `0` or `1`
    /// by adding a constraint in the circuit.
    ///
    /// Note that using this constraint with whatever [`Witness`] that
    /// is not representing a value equalling 0 or 1, will always force the
    /// equation to fail.
    pub fn component_boolean(&mut self, a: Witness) {
        let zero = Self::ZERO;
        let constraint = Constraint::new()
            .mult(1)
            .output(-BlsScalar::one())
            .a(a)
            .b(a)
            .c(a)
            .d(zero);

        self.append_gate(constraint);
    }

    /// Decomposes `scalar` into an array truncated to `N` bits (max 256) in
    /// little endian.
    /// The `scalar` for 4, for example, would be deconstructed into the array
    /// `[0, 0, 1]` for `N = 3` and `[0, 0, 1, 0, 0]` for `N = 5`.
    ///
    /// Asserts the reconstruction of the bits to be equal to `scalar`. So with
    /// the above example, the deconstruction of 4 for `N < 3` would result in
    /// an unsatisfied circuit.
    ///
    /// Consumes `2 · N + 1` gates
    pub fn component_decomposition<const N: usize>(
        &mut self,
        scalar: Witness,
    ) -> [Witness; N] {
        // Static assertion
        assert!(0 < N && N <= 256);

        let mut decomposition = [Self::ZERO; N];

        let acc = Self::ZERO;
        let acc = self[scalar]
            .to_bits()
            .iter()
            .enumerate()
            .zip(decomposition.iter_mut())
            .fold(acc, |acc, ((i, bit), w_bit)| {
                *w_bit = self.append_witness(BlsScalar::from(*bit as u64));

                self.component_boolean(*w_bit);

                let constraint = Constraint::new()
                    .left(BlsScalar::pow_of_2(i as u64))
                    .right(1)
                    .a(*w_bit)
                    .b(acc);

                self.gate_add(constraint)
            });

        self.assert_equal(acc, scalar);

        decomposition
    }

    /// Conditionally selects identity as [`WitnessPoint`] based on an input
    /// bit.
    ///
    /// bit == 1 => a,
    /// bit == 0 => identity,
    ///
    /// `bit` is expected to be constrained by
    /// [`Composer::component_boolean`]
    pub fn component_select_identity(
        &mut self,
        bit: Witness,
        a: WitnessPoint,
    ) -> WitnessPoint {
        let x = self.component_select_zero(bit, *a.x());
        let y = self.component_select_one(bit, *a.y());

        WitnessPoint::new(x, y)
    }

    /// Evaluate `jubjub · point` as a [`WitnessPoint`]
    pub fn component_mul_point(
        &mut self,
        jubjub: Witness,
        point: WitnessPoint,
    ) -> WitnessPoint {
        // Turn scalar into bits
        let scalar_bits = self.component_decomposition::<252>(jubjub);

        let mut result = Self::IDENTITY;

        for bit in scalar_bits.iter().rev() {
            result = self.component_add_point(result, result);

            let point_to_add = self.component_select_identity(*bit, point);
            result = self.component_add_point(result, point_to_add);
        }

        result
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => a,
    /// bit == 0 => b,
    ///
    /// `bit` is expected to be constrained by
    /// [`Composer::component_boolean`]
    pub fn component_select(
        &mut self,
        bit: Witness,
        a: Witness,
        b: Witness,
    ) -> Witness {
        // bit * a
        let constraint = Constraint::new().mult(1).a(bit).b(a);
        let bit_times_a = self.gate_mul(constraint);

        // 1 - bit
        let constraint =
            Constraint::new().left(-BlsScalar::one()).constant(1).a(bit);
        let one_min_bit = self.gate_add(constraint);

        // (1 - bit) * b
        let constraint = Constraint::new().mult(1).a(one_min_bit).b(b);
        let one_min_bit_b = self.gate_mul(constraint);

        // [ (1 - bit) * b ] + [ bit * a ]
        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .a(one_min_bit_b)
            .b(bit_times_a);
        self.gate_add(constraint)
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => value,
    /// bit == 0 => 1,
    ///
    /// `bit` is expected to be constrained by
    /// [`Composer::component_boolean`]
    pub fn component_select_one(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        let b = self[bit];
        let v = self[value];

        let f_x = BlsScalar::one() - b + (b * v);
        let f_x = self.append_witness(f_x);

        let constraint = Constraint::new()
            .mult(1)
            .left(-BlsScalar::one())
            .output(-BlsScalar::one())
            .constant(1)
            .a(bit)
            .b(value)
            .c(f_x);

        self.append_gate(constraint);

        f_x
    }

    /// Conditionally selects a [`WitnessPoint`] based on an input bit.
    ///
    /// bit == 1 => a,
    /// bit == 0 => b,
    ///
    /// `bit` is expected to be constrained by
    /// [`Composer::component_boolean`]
    pub fn component_select_point(
        &mut self,
        bit: Witness,
        a: WitnessPoint,
        b: WitnessPoint,
    ) -> WitnessPoint {
        let x = self.component_select(bit, *a.x(), *b.x());
        let y = self.component_select(bit, *a.y(), *b.y());

        WitnessPoint::new(x, y)
    }

    /// Conditionally selects a [`Witness`] based on an input bit.
    ///
    /// bit == 1 => value,
    /// bit == 0 => 0,
    ///
    /// `bit` is expected to be constrained by
    /// [`Composer::component_boolean`]
    pub fn component_select_zero(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        let constraint = Constraint::new().mult(1).a(bit).b(value);

        self.gate_mul(constraint)
    }

    /// Constrains a [`Witness`] to the range `[0, 2^BITS)`, for any (possibly
    /// odd) compile-time `BITS` up to `256`.
    ///
    /// This is the bit-width-native range check. Even widths use the base-4
    /// quad decomposition; an odd width peels off the most-significant bit as a
    /// boolean and quad-checks the even remainder, so the cost is essentially
    /// that of the even check.
    ///
    /// Prefer this over the bit-pair-counted [`Self::component_range`]: `BITS`
    /// is the actual bit width, with no `× 2` to track.
    ///
    /// A canonical `BlsScalar` is below `2^255`, so any `BITS >= 255` is
    /// satisfied by every witness: the check still emits its gates but
    /// constrains nothing.
    pub fn component_range_bits<const BITS: usize>(
        &mut self,
        witness: Witness,
    ) {
        // `range_check` recomposes a witness < 2^256, so wider checks are
        // meaningless; reject them at compile time rather than silently
        // capping.
        const {
            assert!(
                BITS <= 256,
                "BITS must be <= 256: a witness is at most 256 bits wide"
            )
        };

        self.range_check(witness, BITS);
    }

    /// Adds a range-constraint gate that checks and constrains a [`Witness`]
    /// to be encoded in at most `num_bits = BIT_PAIRS * 2` bits, which means
    /// that the underlying [`BlsScalar`] of the [`Witness`] will be within the
    /// range `[0, 2^num_bits[`, where `num_bits` is dividable by two.
    ///
    /// This function adds:
    /// (num_bits - 1)/8 + 9 gates, when num_bits > 0,
    /// and 7 gates, when num_bits = 0
    /// to the circuit description.
    /// Widths above `BIT_PAIRS = 128` are clamped to 256 bits rather than
    /// rejected, so they all mean the same check.
    #[deprecated(note = "this counts bit-pairs, an easy 2x footgun. Use \
        `component_range_bits::<BITS>`, which counts bits directly: for \
        `N <= 128` replace `component_range::<N>` with \
        `component_range_bits::<2 * N>`; a wider `N` was clamped to 256 bits, \
        so it becomes `component_range_bits::<256>`.")]
    pub fn component_range<const BIT_PAIRS: usize>(
        &mut self,
        witness: Witness,
    ) {
        // Delegates to the shared base-4 core: `BIT_PAIRS` bit-pairs is `2 *
        // BIT_PAIRS` bits, capped at 256. The core emits the same base-4
        // decomposition this entry point checks, so the gate layout — and thus
        // the verifier key — is identical for every caller.
        self.range_check_even(witness, cmp::min(BIT_PAIRS * 2, 256));
    }

    /// Extract the low `N` bits of `witness` as a new [`Witness`], canonically
    /// bound to its input.
    ///
    /// This is the truncation primitive: it proves `low = witness mod 2^N`
    /// directly via the relation `witness = high * 2^N + low`, with a range
    /// check on `low` (`N` bits), a range check on `high` (the remaining
    /// `255 - N` bits), the linear binding gate, and a canonical `< r` guard so
    /// the `(high, low)` split cannot alias the non-canonical representation
    /// `witness + r`. `N` may be odd.
    ///
    /// `append_logic_xor::<BIT_PAIRS>(witness, ZERO)` also yields the low bits,
    /// but it is a bitwise operator pressed into a truncation role: it pays for
    /// the full bitwise widget over the discarded high bits and its width is a
    /// bit-pair count, not a bit count. Prefer `component_truncate` when the
    /// intent is "take the low `N` bits"; reach for the logic gate when the
    /// intent is an actual bitwise `XOR`.
    ///
    /// Cost: the gadget range-checks the full `N + (255 - N)` split plus a
    /// same-width canonical guard, so the decomposed width — and with it the
    /// gate count — is essentially independent of `N`: 84-88 gates across the
    /// whole range. That is cheaper than `append_logic_xor::<N / 2>(x, ZERO)`
    /// at every width, and the gap widens with `N`, since the logic gadget pays
    /// for its per-quad loop on top of the same binding: 88 against 172 gates
    /// at 2 bits, 88 against 234 at 250.
    ///
    /// `N` is capped at `254` at compile time: a canonical `BlsScalar` is 255
    /// bits, so a wider truncation would leave the high part with less than one
    /// bit and the canonical guard ill-defined.
    pub fn component_truncate<const N: usize>(
        &mut self,
        witness: Witness,
    ) -> Witness {
        // A canonical `BlsScalar` is 255 bits, so the truncation binding below
        // is only canonical up to 254 bits. A wider width would silently drop
        // input bits, so it is a hard compile-time error rather than a quiet
        // cap.
        const {
            assert!(
                N <= 254,
                "N must be <= 254: truncation operates on at most 254 bits"
            )
        };

        // Split the low `N` bits off `witness` as a bounded witness, then bind
        // it back to `witness` through the shared truncation split.
        let low_value = recompose_bits(&self[witness].to_bits(), 0, N);
        let low = self.append_witness(low_value);
        self.range_check(low, N);
        self.bind_truncation_split(witness, low, N);

        low
    }

    /// Constrain `(high, low)` to be the canonical split of a field element at
    /// bit `num_bits`, i.e. `high * 2^num_bits + low < r`. This adds only the
    /// `< r` guard, rejecting the single non-canonical alias `witness + r`; it
    /// does not bound `low` or `high` itself.
    ///
    /// Caller MUST range-check both operands before calling — `low` to
    /// `[0, 2^num_bits)` and `high` to `[0, 2^(255 - num_bits))` — otherwise
    /// the split is not unique and the binding is unsound. This is the
    /// shared core for every truncation caller; the obligation is not
    /// enforced in-gate.
    fn assert_canonical_truncation(
        &mut self,
        high: Witness,
        low: Witness,
        num_bits: usize,
    ) {
        let high_bits = 255 - num_bits;

        // Modulus-derived bounds: write `r - 1 = r_high * 2^num_bits + r_low`.
        // The split is canonical (i.e. `< r`, not `< 2r`) iff `(high, low) <=
        // (r_high, r_low)` lexicographically.
        let modulus_bits = (-BlsScalar::one()).to_bits();
        let r_low = recompose_bits(&modulus_bits, 0, num_bits);
        let r_high = recompose_bits(&modulus_bits, num_bits, 256);

        // Enforce `high <= r_high` via `diff = r_high - high in [0,
        // 2^high_bits)`.
        let diff = self.gate_add(
            Constraint::new()
                .left(-BlsScalar::one())
                .a(high)
                .constant(r_high),
        );
        self.range_check(diff, high_bits);

        // is_top = 1 iff high == r_high (diff == 0). Standard is-zero gadget:
        // set `product = diff * inverse` and `is_top = 1 - product`, then the
        // final gate `diff * is_top = 0` pins everything.
        let diff_inverse = self[diff].invert().unwrap_or(BlsScalar::zero());
        let inverse = self.append_witness(diff_inverse);
        let product =
            self.gate_mul(Constraint::new().mult(1).a(diff).b(inverse));
        // is_top = 1 - product
        let is_top = self.gate_add(
            Constraint::new()
                .left(-BlsScalar::one())
                .a(product)
                .constant(1),
        );
        // diff * is_top = 0. This alone pins is_top to exactly `[diff == 0]`,
        // so no explicit `component_boolean(is_top)` is needed. If diff == 0,
        // then product = 0 and is_top = 1 - 0 = 1. If diff != 0, this gate
        // forces is_top = 0, which forces product = 1 and hence the prover to
        // supply inverse = diff^-1. Either way is_top is 0 or 1; no other value
        // satisfies the system, so a boolean constraint would be redundant.
        self.append_gate(Constraint::new().mult(1).a(diff).b(is_top));

        // When high == r_high, require low <= r_low (so the value is < r). The
        // guard is `is_top * (r_low - low)`, which must lie in `[0,
        // 2^num_bits)`: for `low > r_low` it underflows to a huge field
        // element and fails the range check; for `high < r_high` it is zero
        // (canonicity already holds).
        let r_low_minus_low = self.gate_add(
            Constraint::new()
                .left(-BlsScalar::one())
                .a(low)
                .constant(r_low),
        );
        let guard = self
            .gate_mul(Constraint::new().mult(1).a(is_top).b(r_low_minus_low));
        self.range_check(guard, num_bits);
    }

    /// Constrain `value` to lie in `[0, 2^num_bits)`, for any (possibly odd)
    /// runtime `num_bits`. A runtime-sized, odd-capable counterpart to
    /// [`Self::component_range`], whose `const BIT_PAIRS` entry point can only
    /// size even widths known at compile time.
    ///
    /// Even widths use the quad-based [`Self::range_check_even`] (the same
    /// width-4 base-4 decomposition as `component_range`); an odd width peels
    /// off the most-significant bit as a boolean and quad-checks the even
    /// remainder, so the cost is essentially that of the even check.
    fn range_check(&mut self, value: Witness, num_bits: usize) {
        if num_bits % 2 == 0 {
            self.range_check_even(value, num_bits);
            return;
        }

        // value == lower + top_bit * 2^(num_bits - 1), with `lower` in
        // `[0, 2^(num_bits - 1))` and `top_bit` boolean — so value <
        // 2^num_bits.
        let top = num_bits - 1;
        let value_bits = self[value].to_bits();
        let lower_value = recompose_bits(&value_bits, 0, top);
        let top_bit_value = BlsScalar::from(value_bits[top] as u64);

        let lower = self.append_witness(lower_value);
        self.range_check_even(lower, top);

        let top_bit = self.append_witness(top_bit_value);
        self.component_boolean(top_bit);

        let recomposed = self.gate_add(
            Constraint::new()
                .left(1)
                .right(BlsScalar::pow_of_2(top as u64))
                .a(lower)
                .b(top_bit),
        );
        self.assert_equal(recomposed, value);
    }

    /// Constrain `value` to lie in `[0, 2^num_bits)` for an even runtime
    /// `num_bits` (`<= 256`). This is the shared base-4 decomposition that
    /// [`Self::component_range`] and the even path of [`Self::range_check`]
    /// delegate to — the single source of truth for the width-4 range layout.
    fn range_check_even(&mut self, witness: Witness, num_bits: usize) {
        // if num_bits = 0 constrain witness to 0
        if num_bits == 0 {
            let constraint = Constraint::new().left(1).a(witness);
            self.append_gate(constraint);
            return;
        }

        // convert witness to bit representation and reverse
        let bits = self[witness];
        let bit_iter = BitIterator8::new(bits.to_bytes());
        let mut bits: Vec<_> = bit_iter.collect();
        bits.reverse();

        // each gate holds 4 quads (2 bits each), so one gate accumulates 8 bits
        let mut num_gates = num_bits >> 3;
        if num_bits % 8 != 0 {
            num_gates += 1;
        }

        // a gate holds 4 quads
        let num_quads = num_gates * 4;

        // the wires are left-padded with the difference between the quads count
        // and the bits argument
        let pad = 1 + (((num_quads << 1) - num_bits) >> 1);

        // last gate is reserved for either the genesis quad or the padding
        let used_gates = num_gates + 1;

        let base = Constraint::range(&Constraint::new());
        let mut constraints = vec![base; used_gates];

        let mut accumulators: Vec<Witness> = Vec::new();
        let mut accumulator = BlsScalar::zero();
        let four = BlsScalar::from(4);

        for i in pad..=num_quads {
            // convert each pair of bits to quads
            let bit_index = (num_quads - i) << 1;
            let q_0 = bits[bit_index] as u64;
            let q_1 = bits[bit_index + 1] as u64;
            let quad = q_0 + (2 * q_1);

            accumulator = four * accumulator;
            accumulator += BlsScalar::from(quad);

            let accumulator_var = self.append_witness(accumulator);
            accumulators.push(accumulator_var);

            let idx = i / 4;
            // wires fill D, C, B, A within each gate as `i` advances
            let wire = [
                WiredWitness::D,
                WiredWitness::C,
                WiredWitness::B,
                WiredWitness::A,
            ][i % 4];

            constraints[idx].set_witness(wire, accumulator_var);
        }

        // last constraint is zeroed as it is reserved for the genesis quad or
        // padding
        if let Some(c) = constraints.last_mut() {
            *c = Constraint::new();
        }

        if let Some(accumulator) = accumulators.last() {
            if let Some(c) = constraints.last_mut() {
                c.set_witness(WiredWitness::D, *accumulator);
            }
        }

        constraints
            .into_iter()
            .for_each(|c| self.append_custom_gate(c));

        if let Some(accumulator) = accumulators.last() {
            self.assert_equal(*accumulator, witness);
        }
    }

    /// Evaluate and return `o` by appending a new constraint into the circuit.
    ///
    /// Set `q_O = (-1)` and override the output of the constraint with:
    /// `c := q_L · a + q_R · b + q_F · d + q_C + PI`
    pub fn gate_add(&mut self, s: Constraint) -> Witness {
        let s = Constraint::arithmetic(&s).output(-BlsScalar::one());

        let c = self
            .append_evaluated_output(s)
            .expect("output selector is -1");
        let s = s.c(c);

        self.append_gate(s);

        c
    }

    /// Evaluate and return `c` by appending a new constraint into the circuit.
    ///
    /// Set `q_O = (-1)` and override the output of the constraint with:
    /// `c := q_M · a · b + q_F · d + q_C + PI`
    pub fn gate_mul(&mut self, s: Constraint) -> Witness {
        let s = Constraint::arithmetic(&s).output(-BlsScalar::one());

        let c = self
            .append_evaluated_output(s)
            .expect("output selector is -1");
        let s = s.c(c);

        self.append_gate(s);

        c
    }

    /// Prove a circuit with a composer initialized with dummy gates
    pub fn prove<C>(constraints: usize, circuit: &C) -> Result<Self, Error>
    where
        C: Circuit,
    {
        let mut composer = Self::initialized();

        circuit.circuit(&mut composer)?;

        // assert that the circuit has the same amount of constraints as the
        // circuit description
        let description_size = composer.constraints();
        if description_size != constraints {
            return Err(Error::InvalidCircuitSize(
                description_size,
                constraints,
            ));
        }

        composer.runtime().event(RuntimeEvent::ProofFinished);

        Ok(composer)
    }

    pub(crate) fn public_input_indexes(&self) -> Vec<usize> {
        let mut public_input_indexes: Vec<_> =
            self.public_inputs.keys().copied().collect();

        public_input_indexes.as_mut_slice().sort();

        public_input_indexes
    }

    pub(crate) fn public_inputs(&self) -> Vec<BlsScalar> {
        self.public_input_indexes()
            .iter()
            .filter_map(|idx| self.public_inputs.get(idx).copied())
            .collect()
    }

    pub(crate) fn dense_public_inputs(
        public_input_indexes: &[usize],
        public_inputs: &[BlsScalar],
        size: usize,
    ) -> Vec<BlsScalar> {
        let mut dense_public_inputs = vec![BlsScalar::zero(); size];

        public_input_indexes
            .iter()
            .zip(public_inputs.iter())
            .for_each(|(idx, pi)| dense_public_inputs[*idx] = *pi);

        dense_public_inputs
    }
}
