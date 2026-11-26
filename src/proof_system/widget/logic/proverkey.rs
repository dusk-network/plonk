// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
use dusk_bls12_381::BlsScalar;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Serialize,
    ser::{ScratchSpace, Serializer},
};

use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearization_poly::ProofEvaluations;

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

#[derive(Clone, Copy)]
pub(crate) struct LogicChallenges {
    challenge: BlsScalar,
    kappa: BlsScalar,
    kappa_sq: BlsScalar,
    kappa_cu: BlsScalar,
    kappa_qu: BlsScalar,
    eighty_one: BlsScalar,
    eighty_three: BlsScalar,
}

impl LogicChallenges {
    pub(crate) fn new(logic_separation_challenge: &BlsScalar) -> Self {
        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;
        Self {
            challenge: *logic_separation_challenge,
            kappa,
            kappa_sq,
            kappa_cu,
            kappa_qu,
            eighty_one: BlsScalar::from(81),
            eighty_three: BlsScalar::from(83),
        }
    }
}

impl ProverKey {
    #[cfg(test)]
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        logic_separation_challenge: &BlsScalar,
        a_i: &BlsScalar,
        a_i_w: &BlsScalar,
        b_i: &BlsScalar,
        b_i_w: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        d_i_w: &BlsScalar,
    ) -> BlsScalar {
        let challenges = LogicChallenges::new(logic_separation_challenge);
        self.compute_quotient_i_with_challenges(
            index,
            &challenges,
            a_i,
            a_i_w,
            b_i,
            b_i_w,
            c_i,
            d_i,
            d_i_w,
        )
    }

    #[inline]
    pub(crate) fn compute_quotient_i_with_challenges(
        &self,
        index: usize,
        challenges: &LogicChallenges,
        a_i: &BlsScalar,
        a_i_w: &BlsScalar,
        b_i: &BlsScalar,
        b_i_w: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        d_i_w: &BlsScalar,
    ) -> BlsScalar {
        let q_logic_i = &self.q_logic.1[index];
        if *q_logic_i == BlsScalar::zero() {
            return BlsScalar::zero();
        }
        let q_c_i = &self.q_c.1[index];

        let a = a_i_w - a_i.double().double();
        let c_0 = delta(a);

        let b = b_i_w - b_i.double().double();
        let c_1 = delta(b) * challenges.kappa;

        let d = d_i_w - d_i.double().double();
        let c_2 = delta(d) * challenges.kappa_sq;

        let w = c_i;
        let c_3 = (w - a * b) * challenges.kappa_cu;

        let c_4 = delta_xor_and_with_constants(
            &a,
            &b,
            w,
            &d,
            q_c_i,
            &challenges.eighty_one,
            &challenges.eighty_three,
        ) * challenges.kappa_qu;

        q_logic_i * (c_3 + c_0 + c_1 + c_2 + c_4) * challenges.challenge
    }

    pub(crate) fn linearization_scalar(
        logic_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> BlsScalar {
        let four = BlsScalar::from(4);

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = evaluations.a_w_eval - four * evaluations.a_eval;
        let c_0 = delta(a);

        let b = evaluations.b_w_eval - four * evaluations.b_eval;
        let c_1 = delta(b) * kappa;

        let d = evaluations.d_w_eval - four * evaluations.d_eval;
        let c_2 = delta(d) * kappa_sq;

        let w = evaluations.c_eval;
        let c_3 = (w - a * b) * kappa_cu;

        let c_4 =
            delta_xor_and(&a, &b, &w, &d, &evaluations.q_c_eval) * kappa_qu;

        (c_0 + c_1 + c_2 + c_3 + c_4) * logic_separation_challenge
    }

    #[cfg(test)]
    pub(crate) fn compute_linearization(
        &self,
        logic_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let t =
            Self::linearization_scalar(logic_separation_challenge, evaluations);
        &self.q_logic.0 * &t
    }
}

// Computes f(f-1)(f-2)(f-3)
#[inline]
pub(crate) fn delta(f: BlsScalar) -> BlsScalar {
    let one = BlsScalar::one();
    let f_1 = f - one;
    let f_2 = f_1 - one;
    let f_3 = f_2 - one;
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
    delta_xor_and_with_constants(
        a,
        b,
        w,
        c,
        q_c,
        &BlsScalar::from(81),
        &BlsScalar::from(83),
    )
}

#[allow(non_snake_case)]
#[inline]
fn delta_xor_and_with_constants(
    a: &BlsScalar,
    b: &BlsScalar,
    w: &BlsScalar,
    c: &BlsScalar,
    q_c: &BlsScalar,
    eighty_one: &BlsScalar,
    eighty_three: &BlsScalar,
) -> BlsScalar {
    let apb = a + b;
    let three_apb = apb.double() + apb;
    let nine_apb = three_apb.double() + three_apb;
    let eighteen_apb = nine_apb.double();
    let twenty_seven_apb = eighteen_apb + nine_apb;
    let eighty_one_apb = twenty_seven_apb.double() + twenty_seven_apb;

    let sq_sum = a.square() + b.square();
    let nine_sq_sum = sq_sum.double().double().double() + sq_sum;
    let eighteen_sq_sum = nine_sq_sum.double();

    let four_w = w.double().double();
    let F = w
        * (w * (four_w - eighteen_apb + eighty_one) + eighteen_sq_sum
            - eighty_one_apb
            + eighty_three);

    let three_c = c.double() + c;
    let nine_c = three_c.double() + three_c;
    let E = (three_apb + three_c) - F.double();
    let B = q_c * (nine_c - three_apb);
    B + E
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_xor_and_matches_textbook_formula() {
        for seed in 0..32u64 {
            let a = BlsScalar::from(seed * 7 + 1);
            let b = BlsScalar::from(seed * 11 + 2);
            let w = BlsScalar::from(seed * 13 + 3);
            let c = BlsScalar::from(seed * 17 + 4);
            let q_c = BlsScalar::from(seed * 19 + 5);

            let f_ref = w
                * (w * (BlsScalar::from(4) * w
                    - BlsScalar::from(18) * (a + b)
                    + BlsScalar::from(81))
                    + BlsScalar::from(18) * (a.square() + b.square())
                    - BlsScalar::from(81) * (a + b)
                    + BlsScalar::from(83));
            let e_ref =
                BlsScalar::from(3) * (a + b + c) - BlsScalar::from(2) * f_ref;
            let b_ref =
                q_c * (BlsScalar::from(9) * c - BlsScalar::from(3) * (a + b));
            assert_eq!(delta_xor_and(&a, &b, &w, &c, &q_c), b_ref + e_ref);
        }
    }
}
