// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Embedded-curve point gadgets: allocation, equality, the prime-order
//! subgroup check, group arithmetic and variable-base scalar multiplication.

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{EDWARDS_D, JubJubAffine, JubJubExtended, JubJubScalar};

use super::{
    Composer, Constraint, TorsionFreeWitnessPoint, Witness, WitnessPoint,
};
use crate::error::Error;

#[cfg(test)]
mod torsion_free_soundness_tests;

/// The inverse of the curve cofactor in the scalar field: `8⁻¹ mod r`, with
/// `r` the order of the prime-order subgroup. Used to derive the honest
/// witness `Q = [8⁻¹]·P` for [`Composer::assert_torsion_free_point`].
const EIGHT_INV: JubJubScalar = JubJubScalar::from_raw([
    0x5a12e1cbdadee597,
    0x14cd041279990210,
    0x20cce76020268760,
    0x01cfb69d4ca675f5,
]);

impl Composer {
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
}
