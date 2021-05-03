// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::{Evaluations, Polynomial};

use dusk_bls12_381::BlsScalar;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct ProverKey {
    pub(crate) q_c: (Polynomial, Evaluations),
    pub(crate) q_logic: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        logic_separation_challenge: &BlsScalar,
        w_l_i: &BlsScalar,
        w_l_i_next: &BlsScalar,
        w_r_i: &BlsScalar,
        w_r_i_next: &BlsScalar,
        w_o_i: &BlsScalar,
        w_4_i: &BlsScalar,
        w_4_i_next: &BlsScalar,
    ) -> BlsScalar {
        let four = BlsScalar::from(4);

        let q_logic_i = &self.q_logic.1[index];
        let q_c_i = &self.q_c.1[index];

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = w_l_i_next - four * w_l_i;
        let c_0 = delta(a);

        let b = w_r_i_next - four * w_r_i;
        let c_1 = delta(b) * kappa;

        let d = w_4_i_next - four * w_4_i;
        let c_2 = delta(d) * kappa_sq;

        let w = w_o_i;
        let c_3 = (w - a * b) * kappa_cu;

        let c_4 = delta_xor_and(&a, &b, w, &d, &q_c_i) * kappa_qu;

        q_logic_i * (c_3 + c_0 + c_1 + c_2 + c_4) * logic_separation_challenge
    }

    pub(crate) fn compute_linearisation(
        &self,
        logic_separation_challenge: &BlsScalar,
        a_eval: &BlsScalar,
        a_next_eval: &BlsScalar,
        b_eval: &BlsScalar,
        b_next_eval: &BlsScalar,
        c_eval: &BlsScalar,
        d_eval: &BlsScalar,
        d_next_eval: &BlsScalar,
        q_c_eval: &BlsScalar,
    ) -> Polynomial {
        let four = BlsScalar::from(4);
        let q_logic_poly = &self.q_logic.0;

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = a_next_eval - four * a_eval;
        let c_0 = delta(a);

        let b = b_next_eval - four * b_eval;
        let c_1 = delta(b) * kappa;

        let d = d_next_eval - four * d_eval;
        let c_2 = delta(d) * kappa_sq;

        let w = c_eval;
        let c_3 = (w - a * b) * kappa_cu;

        let c_4 = delta_xor_and(&a, &b, w, &d, &q_c_eval) * kappa_qu;

        let t = (c_0 + c_1 + c_2 + c_3 + c_4) * logic_separation_challenge;

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
