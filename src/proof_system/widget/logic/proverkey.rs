// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearization_poly::ProofEvaluations;

use dusk_bls12_381::BlsScalar;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct ProverKey {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_c: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_logic: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        logic_separation_challenge: &BlsScalar,
        a_w_i: &BlsScalar,
        a_w_i_next: &BlsScalar,
        b_w_i: &BlsScalar,
        b_w_i_next: &BlsScalar,
        c_w_i: &BlsScalar,
        d_w_i: &BlsScalar,
        d_w_i_next: &BlsScalar,
    ) -> BlsScalar {
        let four = BlsScalar::from(4);

        let q_logic_i = &self.q_logic.1[index];
        let q_c_i = &self.q_c.1[index];

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = a_w_i_next - four * a_w_i;
        let o_0 = delta(a);

        let b = b_w_i_next - four * b_w_i;
        let o_1 = delta(b) * kappa;

        let d = d_w_i_next - four * d_w_i;
        let o_2 = delta(d) * kappa_sq;

        let w = c_w_i;
        let o_3 = (w - a * b) * kappa_cu;

        let o_4 = delta_xor_and(&a, &b, w, &d, q_c_i) * kappa_qu;

        q_logic_i * (o_3 + o_0 + o_1 + o_2 + o_4) * logic_separation_challenge
    }

    pub(crate) fn compute_linearization(
        &self,
        logic_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let four = BlsScalar::from(4);
        let q_logic_poly = &self.q_logic.0;

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = evaluations.a_next_eval - four * evaluations.a_eval;
        let o_0 = delta(a);

        let b = evaluations.b_next_eval - four * evaluations.b_eval;
        let o_1 = delta(b) * kappa;

        let d = evaluations.d_next_eval - four * evaluations.d_eval;
        let o_2 = delta(d) * kappa_sq;

        let w = evaluations.c_eval;
        let o_3 = (w - a * b) * kappa_cu;

        let o_4 =
            delta_xor_and(&a, &b, &w, &d, &evaluations.q_c_eval) * kappa_qu;

        let t = (o_0 + o_1 + o_2 + o_3 + o_4) * logic_separation_challenge;

        q_logic_poly * &t
    }
}

// Computes f(f-1)(f-2)(f-3)
pub(crate) fn delta(f: BlsScalar) -> BlsScalar {
    let f_1 = f - BlsScalar::one();
    let f_2 = f - BlsScalar::from(2);
    let f_3 = f - BlsScalar::from(3);
    f * f_1 * f_2 * f_3
}

// The identity we want to check is q_logic * A = 0
// A = B + E
// B = q_c * [9c - 3(a+b)]
// E = 3(a+b+c) - 2F
// F = w[w(4w - 18(a+b) + 81) + 18(a^2 + b^2) - 81(a+b) + 83]
#[allow(non_snake_case)]
pub(crate) fn delta_xor_and(
    a: &BlsScalar,
    b: &BlsScalar,
    w: &BlsScalar,
    c: &BlsScalar,
    q_c: &BlsScalar,
) -> BlsScalar {
    let nine = BlsScalar::from(9);
    let two = BlsScalar::from(2);
    let three = BlsScalar::from(3);
    let four = BlsScalar::from(4);
    let eighteen = BlsScalar::from(18);
    let eighty_one = BlsScalar::from(81);
    let eighty_three = BlsScalar::from(83);

    let F = w
        * (w * (four * w - eighteen * (a + b) + eighty_one)
            + eighteen * (a.square() + b.square())
            - eighty_one * (a + b)
            + eighty_three);
    let E = three * (a + b + c) - (two * F);
    let B = q_c * ((nine * c) - three * (a + b));
    B + E
}
