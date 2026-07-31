// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! PLONK turbo composer definitions

use alloc::vec::Vec;
use core::ops;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{EDWARDS_D, JubJubAffine, JubJubExtended, JubJubScalar};
use hashbrown::HashMap;

use crate::error::Error;
use crate::runtime::{Runtime, RuntimeEvent};

mod circuit;
mod compress;
mod constraint_system;
mod fixed_base;
mod gate;
mod logic;
mod range;
mod truncate;

#[cfg(test)]
mod evaluated_output_soundness_tests;

#[cfg(test)]
mod soundness_support;

#[cfg(test)]
mod torsion_free_soundness_tests;

pub(crate) mod permutation;

pub use circuit::Circuit;
pub use constraint_system::{
    Constraint, TorsionFreeWitnessPoint, Witness, WitnessPoint,
};
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

/// The inverse of the curve cofactor in the scalar field: `8⁻¹ mod r`, with
/// `r` the order of the prime-order subgroup. Used to derive the honest
/// witness `Q = [8⁻¹]·P` for [`Composer::assert_torsion_free_point`].
const EIGHT_INV: JubJubScalar = JubJubScalar::from_raw([
    0x5a12e1cbdadee597,
    0x14cd041279990210,
    0x20cce76020268760,
    0x01cfb69d4ca675f5,
]);

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
    /// Identity point representation inside the constraint system. The
    /// identity is the prime-order subgroup's neutral element, so it carries
    /// the [`TorsionFreeWitnessPoint`] membership by construction.
    pub const IDENTITY: TorsionFreeWitnessPoint =
        TorsionFreeWitnessPoint::new_unchecked(WitnessPoint::new(
            Self::ZERO,
            Self::ONE,
        ));
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

    /// Append a new width-4 gate/constraint.
    ///
    /// The constraint added will enforce the following:
    /// `q_M · a · b  + q_L · a + q_R · b + q_O · o + q_F · d + q_C + PI = 0`.
    pub fn append_gate(&mut self, constraint: Constraint) {
        let constraint = Constraint::arithmetic(&constraint);

        self.append_custom_gate(constraint)
    }

    /// Evaluate an arithmetic constraint, allocate its output, and append the
    /// gate that constrains that output to the inputs.
    ///
    /// For an invertible output selector `q_O`, this solves
    ///
    /// `q_M·a·b + q_L·a + q_R·b + q_O·c + q_F·d + q_C + PI = 0`
    ///
    /// for `c`, appends `c` as a witness, wires it into the constraint, and
    /// appends exactly one active arithmetic gate.
    ///
    /// If `q_O` is zero, no output can be solved for: this returns `None` but
    /// still appends exactly one arithmetic gate enforcing the supplied
    /// polynomial on its input witnesses.
    ///
    /// The appended gate is the soundness boundary. Computing `c` from host
    /// witness values alone is not a circuit constraint: without this row, a
    /// malicious prover could replace `c` while preserving the circuit shape.
    ///
    /// # Circuit compatibility
    ///
    /// Direct callers now receive one arithmetic row and must regenerate their
    /// circuit-specific proving and verifier keys, and any cached compressed
    /// circuit description. [`Self::gate_add`] and [`Self::gate_mul`] still
    /// emit exactly one row, so their circuit layouts are unchanged.
    pub fn append_evaluated_output(
        &mut self,
        mut s: Constraint,
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

        let output = c.map(|c| self.append_witness(c));
        if let Some(output) = output {
            s = s.c(output);
        }
        self.append_gate(s);

        output
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
    /// [`TorsionFreeWitnessPoint`] with its coordinates.
    ///
    /// The constant is validated natively at circuit build: a point outside
    /// the prime-order subgroup errors with
    /// [`Error::JubJubPointNotTorsionFree`] instead of baking an invalid
    /// group element into the circuit description. This is the constant-point
    /// arm of the boundary rule documented on [`TorsionFreeWitnessPoint`].
    pub fn append_constant_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> Result<TorsionFreeWitnessPoint, Error> {
        let affine = affine.into();

        // `is_torsion_free` alone accepts some off-curve coordinate pairs
        // (e.g. `(0, 0)`, which the order-multiplication ladder collapses
        // onto the identity), so the curve equation is checked separately.
        let is_member = affine.is_on_curve()
            & JubJubExtended::from(affine).is_torsion_free();
        if !bool::from(is_member) {
            return Err(Error::JubJubPointNotTorsionFree);
        }

        let x = self.append_constant(affine.get_u());
        let y = self.append_constant(affine.get_v());

        Ok(TorsionFreeWitnessPoint::new_unchecked(WitnessPoint::new(
            x, y,
        )))
    }

    /// Appends a point in affine form as [`WitnessPoint`]
    ///
    /// Creates two public inputs as `(x, y)`
    ///
    /// The returned point is untyped: whether a public point is a prime-order
    /// subgroup element is established outside the circuit, as part of the
    /// verifier's protocol. A caller whose protocol performs that check can
    /// wrap the result with [`TorsionFreeWitnessPoint::new_unchecked`]; see
    /// [`TorsionFreeWitnessPoint`] for the boundary rule.
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

    /// Constrain `point` to lie in the prime-order subgroup of the embedded
    /// curve by consuming 12 gates, returning it as a
    /// [`TorsionFreeWitnessPoint`].
    ///
    /// This is the in-circuit arm of the boundary rule documented on
    /// [`TorsionFreeWitnessPoint`]: call it once, where an untrusted
    /// (prover-supplied) point enters the circuit — group closure then keeps
    /// every derived point valid, so the arithmetic gates never re-check
    /// their inputs.
    ///
    /// The check appends a witness `Q`, constrains it to the curve equation
    /// `-u² + v² = 1 + d·u²·v²` and enforces `point == [8]·Q` through three
    /// constrained doublings. On a cofactor-8 curve the image of
    /// multiplication-by-8 is exactly the prime-order subgroup, so a
    /// satisfying assignment exists if and only if `point` is a prime-order
    /// subgroup element — the identity included, being the subgroup's neutral
    /// element. The semantics match dusk-jubjub's `is_torsion_free`, not its
    /// `is_prime_order` (which additionally excludes the identity): a
    /// consumer that must also rule out the identity point has to constrain
    /// that separately. Soundness rests on the appended constraints alone,
    /// which bind every intermediate witness: the honest witness value
    /// `Q = [8⁻¹]·point` computed here is only structural, and the doubling
    /// chain relies on the completeness of the twisted Edwards addition law
    /// (`a = -1` a square, `d` a non-square), which leaves no exceptional
    /// case with a free witness.
    pub fn assert_torsion_free_point(
        &mut self,
        point: WitnessPoint,
    ) -> TorsionFreeWitnessPoint {
        let u = self[*point.x()];
        let v = self[*point.y()];

        // Honest witness Q = [8⁻¹]·point. An off-curve `point` admits no
        // satisfying `Q` at all; the identity stands in for it so that
        // witness generation stays panic-free and the proof fails at the
        // constraints instead. The branch is on witness data, but it is
        // constant for every honest prover (the point is always on-curve);
        // a dishonest assignment only changes which constraint rejects.
        let point_value = JubJubAffine::from_raw_unchecked(u, v);
        let q = if bool::from(point_value.is_on_curve()) {
            (JubJubExtended::from(point_value) * EIGHT_INV).into()
        } else {
            JubJubAffine::identity()
        };

        self.assert_torsion_free_gates(point, q);

        TorsionFreeWitnessPoint::new_unchecked(point)
    }

    /// The constraints behind [`Self::assert_torsion_free_point`], taking the
    /// witness `Q` as a parameter. Kept separate so the soundness tests can
    /// stand in for a malicious prover and inject an arbitrary `Q`.
    fn assert_torsion_free_gates(
        &mut self,
        point: WitnessPoint,
        q: JubJubAffine,
    ) {
        let q = self.append_point(q);
        let qu = *q.x();
        let qv = *q.y();

        // Constrain Q to the curve: -u² + v² - d·u²·v² - 1 = 0
        let u2 = self.gate_mul(Constraint::new().mult(1).a(qu).b(qu));
        let v2 = self.gate_mul(Constraint::new().mult(1).a(qv).b(qv));
        let u2v2 = self.gate_mul(Constraint::new().mult(1).a(u2).b(v2));
        self.append_gate(
            Constraint::new()
                .left(-BlsScalar::one())
                .a(u2)
                .right(1)
                .b(v2)
                .output(-EDWARDS_D)
                .c(u2v2)
                .constant(-BlsScalar::one()),
        );

        // Constrain point == [8]·Q
        let q2 = self.add_point_gates(q, q);
        let q4 = self.add_point_gates(q2, q2);
        let q8 = self.add_point_gates(q4, q4);
        self.assert_equal_point(point, q8);
    }

    /// Negates a curve point by consuming 1 gate.
    ///
    /// Negation preserves subgroup membership, so the
    /// [`TorsionFreeWitnessPoint`] type carries through.
    pub fn component_neg_point(
        &mut self,
        p: TorsionFreeWitnessPoint,
    ) -> TorsionFreeWitnessPoint {
        // We negate the 'x' coordinate of the point 'p', so that
        // neg_point = (-p.x, p.y)
        let constraint = Constraint::new().left(-BlsScalar::one()).a(*p.x());
        let neg_p_x = self.gate_mul(constraint);

        TorsionFreeWitnessPoint::new_unchecked(WitnessPoint::new(
            neg_p_x,
            *p.y(),
        ))
    }

    /// Subtracts a curve point from another by consuming 3 gates.
    ///
    /// Subgroup membership of the inputs is carried by the
    /// [`TorsionFreeWitnessPoint`] type — see its documentation for the
    /// boundary rule on how membership is established. Group closure keeps
    /// the difference in the subgroup, hence the typed return.
    pub fn component_sub_point(
        &mut self,
        a: TorsionFreeWitnessPoint,
        b: TorsionFreeWitnessPoint,
    ) -> TorsionFreeWitnessPoint {
        // We negate the point 'b'
        let neg_b = self.component_neg_point(b);

        // We return a + (-b)
        self.component_add_point(a, neg_b)
    }

    /// Adds two curve points by consuming 2 gates.
    ///
    /// The gate constrains only the twisted-Edwards addition identity; it
    /// does **not** re-check that `a`/`b` lie on the curve or in the
    /// prime-order subgroup. Subgroup membership of the inputs is instead
    /// carried by the [`TorsionFreeWitnessPoint`] type — see its
    /// documentation for the boundary rule on how membership is established.
    /// Group closure keeps the sum in the subgroup, hence the typed return.
    pub fn component_add_point(
        &mut self,
        a: TorsionFreeWitnessPoint,
        b: TorsionFreeWitnessPoint,
    ) -> TorsionFreeWitnessPoint {
        let sum = self.add_point_gates(a.into(), b.into());

        TorsionFreeWitnessPoint::new_unchecked(sum)
    }

    /// The gates behind [`Self::component_add_point`], operating on untyped
    /// points. Kept separate so in-crate gadgets (the torsion-free check and
    /// its soundness tests) can emit the addition gates for points whose
    /// membership is not yet established.
    fn add_point_gates(
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

    /// Conditionally selects identity as [`TorsionFreeWitnessPoint`] based on
    /// an input bit, consuming 3 gates.
    ///
    /// bit == 1 => a,
    /// bit == 0 => identity,
    ///
    /// `bit` is constrained to be boolean by this component: both outcomes
    /// are then subgroup members, so the [`TorsionFreeWitnessPoint`] type
    /// carries through. Without that constraint a non-boolean assignment `t`
    /// would evaluate to `(t·x, 1 - t + t·y)` — generally not even on the
    /// curve — while still carrying the membership type.
    pub fn component_select_identity(
        &mut self,
        bit: Witness,
        a: TorsionFreeWitnessPoint,
    ) -> TorsionFreeWitnessPoint {
        self.component_boolean(bit);
        let selected = self.select_identity_gates(bit, a);

        // With `bit` constrained boolean, both mux outcomes are `a` and the
        // identity — subgroup members either way.
        TorsionFreeWitnessPoint::new_unchecked(selected)
    }

    /// The gates behind [`Self::component_select_identity`] without the
    /// boolean constraint on `bit`. Like the other private seams, it returns
    /// the untyped point: the caller owns the boolean constraint that makes
    /// the selection a subgroup member.
    fn select_identity_gates(
        &mut self,
        bit: Witness,
        a: TorsionFreeWitnessPoint,
    ) -> WitnessPoint {
        let x = self.component_select_zero(bit, *a.x());
        let y = self.component_select_one(bit, *a.y());

        WitnessPoint::new(x, y)
    }

    /// Evaluate `jubjub · point` as a [`TorsionFreeWitnessPoint`]
    ///
    /// The scalar multiplication does **not** re-check that the `point` base
    /// lies on the curve or in the prime-order subgroup. Subgroup membership
    /// of the base is instead carried by the [`TorsionFreeWitnessPoint`] type
    /// — see its documentation for the boundary rule on how membership is
    /// established. Group closure keeps every multiple in the subgroup, hence
    /// the typed return.
    pub fn component_mul_point(
        &mut self,
        jubjub: Witness,
        point: TorsionFreeWitnessPoint,
    ) -> TorsionFreeWitnessPoint {
        // Turn scalar into bits
        let scalar_bits = self.component_decomposition::<252>(jubjub);

        let mut result = WitnessPoint::from(Self::IDENTITY);

        for bit in scalar_bits.iter().rev() {
            result = self.add_point_gates(result, result);

            // The bits are already boolean-constrained by the decomposition,
            // so the unconstrained seam is sound here and saves a gate per
            // round.
            let point_to_add = self.select_identity_gates(*bit, point);
            result = self.add_point_gates(result, point_to_add);
        }

        TorsionFreeWitnessPoint::new_unchecked(result)
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
    ///
    /// This mux deliberately stays untyped: it is not a group operation, and
    /// selecting between unvalidated points is legitimate. Consequently the
    /// output is only as validated as the chosen input — where the boundary
    /// rule on [`TorsionFreeWitnessPoint`] requires membership, establish it
    /// on the selected point.
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

    /// Evaluate and return `o` by appending a new constraint into the circuit.
    ///
    /// Set `q_O = (-1)` and override the output of the constraint with:
    /// `c := q_L · a + q_R · b + q_F · d + q_C + PI`
    pub fn gate_add(&mut self, s: Constraint) -> Witness {
        let s = Constraint::arithmetic(&s).output(-BlsScalar::one());

        self.append_evaluated_output(s)
            .expect("output selector is -1")
    }

    /// Evaluate and return `c` by appending a new constraint into the circuit.
    ///
    /// Set `q_O = (-1)` and override the output of the constraint with:
    /// `c := q_M · a · b + q_F · d + q_C + PI`
    pub fn gate_mul(&mut self, s: Constraint) -> Witness {
        let s = Constraint::arithmetic(&s).output(-BlsScalar::one());

        self.append_evaluated_output(s)
            .expect("output selector is -1")
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
