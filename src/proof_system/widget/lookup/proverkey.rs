// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::compress;
use crate::fft::{Evaluations, Polynomial};
use crate::plookup::MultiSet;

use dusk_bls12_381::BlsScalar;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ProverKey {
    pub(crate) q_lookup: (Polynomial, Evaluations),
    pub(crate) table_1: (MultiSet, Polynomial, Evaluations),
    pub(crate) table_2: (MultiSet, Polynomial, Evaluations),
    pub(crate) table_3: (MultiSet, Polynomial, Evaluations),
    pub(crate) table_4: (MultiSet, Polynomial, Evaluations),
}

impl ProverKey {
    /// Compute identity check for lookup gates
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        lookup_separation_challenge: &BlsScalar,
        w_l_i: &BlsScalar,
        w_r_i: &BlsScalar,
        w_o_i: &BlsScalar,
        w_4_i: &BlsScalar,
        f_i: &BlsScalar,
        p_i: &BlsScalar,
        p_i_next: &BlsScalar,
        t_i: &BlsScalar,
        t_i_next: &BlsScalar,
        h_1_i: &BlsScalar,
        h_1_i_next: &BlsScalar,
        h_2_i: &BlsScalar,
        l_first_i: &BlsScalar,
        (delta, epsilon): (&BlsScalar, &BlsScalar),
        zeta: &BlsScalar,
    ) -> BlsScalar {
        let l_sep_2 = lookup_separation_challenge.square();
        let l_sep_3 = l_sep_2 * lookup_separation_challenge;

        let one_plus_delta = delta + BlsScalar::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // q_lookup(X) * (a(X) + zeta * b(X) + (zeta^2 * c(X)) + (zeta^3 * d(X)
        // - f(X))) * α_1
        let a = {
            let q_lookup_i = self.q_lookup.1[index];
            let compressed_tuple =
                compress(*w_l_i, *w_r_i, *w_o_i, *w_4_i, *zeta);

            q_lookup_i * (compressed_tuple - f_i) * lookup_separation_challenge
        };

        // L0(X) * (p(X) − 1) * α_1^2
        let b = { l_first_i * (p_i - BlsScalar::one()) * l_sep_2 };

        // p(X) * (1+δ) * (ε+f(X)) * (ε*(1+δ) + t(X) + δt(Xω)) * α_1^3
        let c = {
            let c_1 = epsilon + f_i;
            let c_2 = epsilon_one_plus_delta + t_i + delta * t_i_next;

            p_i * one_plus_delta * c_1 * c_2 * l_sep_3
        };

        // − p(Xω) * (ε*(1+δ) + h1(X) + δ*h2(X)) * (ε*(1+δ) + h2(X) + δ*h1(Xω))
        // * α_1^3
        let d = {
            let d_1 = epsilon_one_plus_delta + h_1_i + delta * h_2_i;
            let d_2 = epsilon_one_plus_delta + h_2_i + delta * h_1_i_next;

            -p_i_next * d_1 * d_2 * l_sep_3
        };

        a + b + c + d
    }

    /// Compute linearisation for lookup gates
    pub(crate) fn compute_linearisation(
        &self,
        a_eval: &BlsScalar,
        b_eval: &BlsScalar,
        c_eval: &BlsScalar,
        d_eval: &BlsScalar,
        f_eval: &BlsScalar,
        t_eval: &BlsScalar,
        t_next_eval: &BlsScalar,
        h_1_eval: &BlsScalar,
        h_2_eval: &BlsScalar,
        p_next_eval: &BlsScalar,
        l1_eval: &BlsScalar,
        p_poly: &Polynomial,
        h_2_poly: &Polynomial,
        (delta, epsilon): (&BlsScalar, &BlsScalar),
        zeta: &BlsScalar,
        lookup_separation_challenge: &BlsScalar,
    ) -> Polynomial {
        let l_sep_2 = lookup_separation_challenge.square();
        let l_sep_3 = l_sep_2 * lookup_separation_challenge;
        let zeta_sq = zeta * zeta;
        let zeta_cu = zeta * zeta_sq;
        let one_plus_delta = delta + BlsScalar::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        //
        // - q_lookup(X) * f_eval * lookup_separation_challenge
        let a = {
            let a_0 =
                a_eval + zeta * b_eval + zeta_sq * c_eval + zeta_cu * d_eval;

            &self.q_lookup.0 * &((a_0 - f_eval) * lookup_separation_challenge)
        };

        // p(X) * L0(z) * α_1^2
        let b = { p_poly * &(l1_eval * l_sep_2) };

        // p(X) * (1 + δ) * (ε + f_bar) * (ε(1+δ) + t_bar + δ*tω_bar) * α_1^3
        let c = {
            let c_0 = epsilon + f_eval;
            let c_1 = epsilon_one_plus_delta + t_eval + delta * t_next_eval;

            p_poly * &(one_plus_delta * c_0 * c_1 * l_sep_3)
        };

        // − pω_bar * (ε(1+δ) + h1_bar + δh2_bar) * h2(X) * α_1^3
        let d = {
            let d_0 = epsilon_one_plus_delta + h_1_eval + delta * h_2_eval;

            h_2_poly * &(-p_next_eval * d_0 * l_sep_3)
        };

        let mut r = a;
        r += &b;
        r += &c;
        r += &d;

        r
    }
}
