// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::compress;
use crate::fft::{Evaluations, Polynomial};

use dusk_bls12_381::BlsScalar;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PlookupProverKey {
    pub q_lookup: (Polynomial, Evaluations),
}

impl PlookupProverKey {
    /// Compute identity check for lookup gates
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        x_i: &BlsScalar,
        omega_inv: &BlsScalar,
        lookup_separation_challenge: &BlsScalar,
        w_l_i: &BlsScalar,
        w_r_i: &BlsScalar,
        w_o_i: &BlsScalar,
        w_4_i: &BlsScalar,
        f_long_i: &BlsScalar,
        f_short_i: &BlsScalar,
        p_i: &BlsScalar,
        p_i_next: &BlsScalar,
        t_i: &BlsScalar,
        t_i_next: &BlsScalar,
        h_1_i: &BlsScalar,
        h_1_i_next: &BlsScalar,
        h_2_i: &BlsScalar,
        h_2_i_next: &BlsScalar,
        l_first_i: &BlsScalar,
        l_last_i: &BlsScalar,
        (delta, epsilon): (&BlsScalar, &BlsScalar),
        zeta: &BlsScalar,
    ) -> BlsScalar {
        let l_sep_2 = lookup_separation_challenge.square();
        let l_sep_3 = l_sep_2 * lookup_separation_challenge.square();
        let l_sep_4 = l_sep_3 * lookup_separation_challenge.square();
        let l_sep_5 = l_sep_4 * lookup_separation_challenge.square();

        let x_minus_omega_inv = x_i - omega_inv;
        let one_plus_delta = delta + BlsScalar::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // q_lookup(X) * (a(X) + zeta * b(X) + (zeta^2 * c(X)) + (zeta^3 * d(X) - f(X))) * α_1
        let a = {
            let q_lookup_i = self.q_lookup.1[index];
            let compressed_tuple = compress(*w_l_i, *w_r_i, *w_o_i, *w_4_i, *zeta);

            q_lookup_i * (compressed_tuple - f_long_i) * lookup_separation_challenge
        };

        // L0(X)*(p(X)−1)*α_1^2
        let b = {
            l_first_i * (p_i - BlsScalar::one()) * l_sep_2
        };

        // (X−1)*p(X)*(1+δ)*(ε+f(X))*(ε*(1+δ)+t(X)+δt(Xω))*α_1^3
        let c = {
            let c_1 = epsilon + f_short_i;
            let c_2 = epsilon_one_plus_delta + t_i + delta * t_i_next;
            
            x_minus_omega_inv * p_i * one_plus_delta * c_1 * c_2 * l_sep_3
        };


        // −(X−1) * p(Xω) * (ε*(1+δ) + h1(X) + δ*h1(Xω)) * (ε*(1+δ) + h2(X) + δ*h2(Xω)) * α_1^3
        let d = {
            let d_1 = epsilon_one_plus_delta + h_1_i + delta * h_1_i_next;
            let d_2 = epsilon_one_plus_delta + h_2_i + delta * h_2_i_next;

            - x_minus_omega_inv * p_i_next * d_1 * d_2 * l_sep_3
        };

        // lagrange_last(X) * (h1(X)−h2(Xω))*α_1^4
        let e = {
            l_last_i * (h_1_i - h_2_i_next) * l_sep_4
        };

        let f = {
            l_last_i * (p_i - BlsScalar::one()) * l_sep_5
        };

        a + b + c + d + e + f
    }

    /// Compute identity check for lookup gates
    pub(crate) fn compute_quotient_i_debug(
        &self,
        index: usize,
        x_i: &BlsScalar,
        omega_inv: &BlsScalar,
        lookup_separation_challenge: &BlsScalar,
        w_l_i: &BlsScalar,
        w_r_i: &BlsScalar,
        w_o_i: &BlsScalar,
        w_4_i: &BlsScalar,
        w_l_i_next: &BlsScalar,
        w_r_i_next: &BlsScalar,
        w_o_i_next: &BlsScalar,
        w_4_i_next: &BlsScalar,
        f_long_i: &BlsScalar,
        f_short_i: &BlsScalar,
        p_i: &BlsScalar,
        p_i_next: &BlsScalar,
        t_i: &BlsScalar,
        t_i_next: &BlsScalar,
        h_1_i: &BlsScalar,
        h_1_i_next: &BlsScalar,
        h_2_i: &BlsScalar,
        h_2_i_next: &BlsScalar,
        l_first_i: &BlsScalar,
        l_last_i: &BlsScalar,
        (delta, epsilon): (&BlsScalar, &BlsScalar),
        zeta: &BlsScalar,
    ) -> (BlsScalar, BlsScalar, BlsScalar, BlsScalar, BlsScalar, BlsScalar) {
        let l_sep_2 = lookup_separation_challenge.square();
        let l_sep_3 = l_sep_2 * lookup_separation_challenge.square();
        let l_sep_4 = l_sep_3 * lookup_separation_challenge.square();
        let l_sep_5 = l_sep_4 * lookup_separation_challenge.square();

        let x_minus_one = x_i - BlsScalar::one();
        let x_minus_omega_inv = x_i - omega_inv;
        let one_plus_delta = delta + BlsScalar::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // q_lookup(X) * (a(X) + zeta * b(X) + (zeta^2 * c(X)) + (zeta^3 * d(X) - f(X))) * α_1
        let a = {
            let q_lookup_i = self.q_lookup.1[index];
            let compressed_tuple = compress(*w_l_i, *w_r_i, *w_o_i, *w_4_i, *zeta);

            q_lookup_i * (compressed_tuple - f_long_i) * lookup_separation_challenge
        };

        // L0(X)*(p(X)−1)*α_1^2
        let b = {
            BlsScalar::zero()//l_first_i * (p_i - BlsScalar::one()) * l_sep_2
        };

        // (X−1)*p(X)*(1+δ)*(ε+f(X))*(ε*(1+δ)+t(X)+δt(Xω))*α_1^3
        let c = {
            let c_1 = epsilon + f_short_i;
            let c_2 = epsilon_one_plus_delta + t_i + delta * t_i_next;
            
            x_minus_omega_inv * p_i * one_plus_delta * c_1 * c_2 * l_sep_3
        };


        // −(X−1) * p(Xω) * (ε*(1+δ) + h1(X) + δ*h1(Xω)) * (ε*(1+δ) + h2(X) + δ*h2(Xω)) * α_1^3
        let d = {
            let d_1 = epsilon_one_plus_delta + h_1_i + delta * h_1_i_next;
            let d_2 = epsilon_one_plus_delta + h_2_i + delta * h_2_i_next;

            - x_minus_omega_inv * p_i_next * d_1 * d_2 * l_sep_3
        };

        // lagrange_last(X) * (h1(X)−h2(Xω))*α_1^4
        let e = {
            l_last_i * (h_1_i - h_2_i_next) * l_sep_4
        };

        let f = {
            BlsScalar::zero() //l_last_i * (p_i - BlsScalar::one()) * l_sep_5
        };
        //println!("a:\n{:?}", a);
        (a, b, c, d, e, f)
    }

    /// Compute linearisation for lookup gates
    pub(crate) fn compute_linearisation(
        &self,
        f_long_eval: &BlsScalar,
        f_short_eval: &BlsScalar,
        t_eval: &BlsScalar,
        t_next_eval: &BlsScalar,
        h_1_eval: &BlsScalar,
        h_1_next_eval: &BlsScalar,
        p_next_eval: &BlsScalar,
        l1_eval: &BlsScalar,
        ln_eval: &BlsScalar,
        p_poly: &Polynomial,
        h_1_poly: &Polynomial,
        h_2_poly: &Polynomial,
        (delta, epsilon): (&BlsScalar, &BlsScalar),
        z_challenge: &BlsScalar,
        lookup_separation_challenge: &BlsScalar,
    ) -> Polynomial {

        let l_sep_2 = lookup_separation_challenge.square();
        let l_sep_3 = l_sep_2 * lookup_separation_challenge.square();
        let l_sep_4 = l_sep_3 * lookup_separation_challenge.square();
        let l_sep_5 = l_sep_4 * lookup_separation_challenge.square();
        
        let z_minus_one = z_challenge - BlsScalar::one();
        let one_plus_delta = delta + BlsScalar::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;
        
        // - q_lookup(X) * f_eval * lookup_separation_challenge
        let a = {    
            &self.q_lookup.0 * &(-f_long_eval * lookup_separation_challenge)
        };

        // p(X)*L0(z)α_1^2
        let b = {
            p_poly * &(l1_eval * l_sep_2)
        };

        // (z − 1)p(X)(1 + δ)(ε + f_bar)(ε(1+δ) + t_bar + δ*tω_bar)α_1^3
        let c = {
            let c_0 = epsilon + f_short_eval;
            let c_1 = epsilon_one_plus_delta + t_eval + delta * t_next_eval;

            p_poly * &(z_minus_one * one_plus_delta * c_0 * c_1 * l_sep_3)
        };

        // −(z−1)*pω_bar*(ε(1+δ)+h1_bar+δh1ω_bar)h2(X)α_1^3
        let d = {
            let d_0 = epsilon_one_plus_delta + h_1_eval + delta * h_1_next_eval;

            h_2_poly * &(- z_minus_one * p_next_eval * d_0 * l_sep_3)
        };

        let e = {
            h_1_poly * &(ln_eval * l_sep_4)
        };

        let f = {
            p_poly * &(ln_eval * l_sep_5)
        };
        
        let mut r = a;
        r += &b;
        r += &c;
        r += &d;
        r += &e;
        r += &f;

        r
    }
}
