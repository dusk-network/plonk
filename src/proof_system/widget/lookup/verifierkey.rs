// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::kzg10::Commitment;
use crate::proof_system::linearisation_poly::ProofEvaluations;
use alloc::vec::Vec;
use dusk_bls12_381::{BlsScalar, G1Affine};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VerifierKey {
    pub(crate) q_lookup: Commitment,
    pub(crate) table_1: Commitment,
    pub(crate) table_2: Commitment,
    pub(crate) table_3: Commitment,
    pub(crate) table_4: Commitment,
}

impl VerifierKey {
    pub(crate) fn compute_linearisation_commitment(
        &self,
        lookup_separation_challenge: &BlsScalar,
        scalars: &mut Vec<BlsScalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
        (delta, epsilon): (&BlsScalar, &BlsScalar),
        zeta: &BlsScalar,
        l1_eval: &BlsScalar,
        t_eval: &BlsScalar,
        t_next_eval: &BlsScalar,
        h_2_comm: G1Affine,
        p_comm: G1Affine,
    ) {
        let l_sep_2 = lookup_separation_challenge.square();
        let l_sep_3 = lookup_separation_challenge * l_sep_2;
        let zeta_sq = zeta * zeta;
        let zeta_cu = zeta * zeta_sq;

        // (a_eval + zeta*b_eval + zeta^2*c_eval + zeta^3d_eval - f_eval) *
        // q_lookup * alpha_1
        let a = {
            let a_0 = evaluations.a_eval
                + zeta * evaluations.b_eval
                + zeta_sq * evaluations.c_eval
                + zeta_cu * evaluations.d_eval;
            let a_1 = evaluations.f_eval;

            (a_0 - a_1) * lookup_separation_challenge
        };

        scalars.push(a);
        points.push(self.q_lookup.0);

        //
        // - (p_next_eval*(epsilon*(1 + delta) + h_1_eval +
        //   delta*h_2_eval)*alpha_1^3)*h_2
        let c = {
            let c_0 = &evaluations.lookup_perm_eval;

            let c_1 = epsilon * (BlsScalar::one() + delta)
                + &evaluations.h_1_eval
                + delta * &evaluations.h_2_eval;

            -c_0 * c_1 * l_sep_3
        };
        scalars.push(c);
        points.push(h_2_comm);

        // (1 + delta)(e + f_eval)(epsilon*(1 + delta) + t_eval + (delta *
        // t_next_eval) * alpha_1^3 + l_1(z) * alpha_1^2
        let d = {
            let d_0 = BlsScalar::one() + delta;

            let d_1 = epsilon + evaluations.f_eval;

            let d_2 =
                (epsilon * d_0 + t_eval + (delta * t_next_eval)) * l_sep_3;

            let d_3 = l1_eval * l_sep_2;

            (d_0 * d_1 * d_2) + d_3
        };

        scalars.push(d);
        points.push(p_comm);
    }
}
