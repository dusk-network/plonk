// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::kzg10::Commitment;
use crate::proof_system::lookup_lineariser::PlookupProofEvaluations;
use dusk_bls12_381::{BlsScalar, G1Affine};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PlookupVerifierKey {
    pub q_lookup: Commitment,
}

impl PlookupVerifierKey {
    pub(crate) fn compute_linearisation_commitment(
        &self,
        lookup_separation_challenge: &BlsScalar,
        scalars: &mut Vec<BlsScalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &PlookupProofEvaluations,
        z_challenge: &BlsScalar,
        (delta, epsilon): (&BlsScalar, &BlsScalar),
        l1_eval: &BlsScalar,
        ln_eval: &BlsScalar,
        t_eval: &BlsScalar,
        t_next_eval: &BlsScalar,
        h_1_comm: G1Affine,
        h_2_comm: G1Affine,
        p_comm: G1Affine,
        omega_inv: &BlsScalar,
    ) {
        let l_sep_2 = lookup_separation_challenge.square();
        let l_sep_3 = lookup_separation_challenge * l_sep_2;
        let l_sep_4 = lookup_separation_challenge * l_sep_3;
        let l_sep_5 = lookup_separation_challenge * l_sep_4;

        // - f_eval * q_lookup * alpha_1
        let a = -evaluations.f_long_eval * lookup_separation_challenge;
        scalars.push(a);
        points.push(self.q_lookup.0);

        // l_n(z) * alpha_1^4
        let b = { ln_eval * l_sep_4 };
        scalars.push(b);
        points.push(h_1_comm);

        // - ((z - omega_inv)*p_next_eval*(epsilon*(1 + delta) + h_1_eval + delta*h_1_next_eval)*alpha_1^3)*h_2
        let c = {
            let c_0 = -(z_challenge - omega_inv);

            let c_1 = &evaluations.lookup_perm_eval;

            let c_2 = epsilon * (BlsScalar::one() + delta)
                + &evaluations.h_1_eval
                + delta * &evaluations.h_1_next_eval;

            c_0 * c_1 * c_2 * l_sep_3
        };
        scalars.push(c);
        points.push(h_2_comm);

        // (z - omega_inv)(1 + delta)(e + f_eval)(epsilon(1 + delta) + t_eval + (delta * t_next_eval) * alpha_1^3 + l_1(z) * alpha_1^2 + l_n(z) * alpha_1^5)
        let d = {
            let d_0 = z_challenge - omega_inv;

            let d_1 = BlsScalar::one() + delta;

            let d_2 = epsilon + evaluations.f_short_eval;

            let d_3 = (epsilon * d_1 + t_eval + (delta * t_next_eval)) * l_sep_3;

            let d_4 = l1_eval * l_sep_2;

            let d_5 = ln_eval * l_sep_5;

            (d_0 * d_1 * d_2 * d_3) + d_4 + d_5
        };

        scalars.push(d);
        points.push(p_comm);
    }
}
