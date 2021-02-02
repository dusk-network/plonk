// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{delta, delta_xor_and};
use crate::commitment_scheme::kzg10::Commitment;
use crate::proof_system::linearisation_poly::ProofEvaluations;
use crate::proof_system::lookup_lineariser::PlookupProofEvaluations;
use dusk_bls12_381::{BlsScalar, G1Affine};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct VerifierKey {
    pub q_c: Commitment,
    pub q_logic: Commitment,
}

impl VerifierKey {
    pub(crate) fn compute_linearisation_commitment(
        &self,
        logic_separation_challenge: &BlsScalar,
        scalars: &mut Vec<BlsScalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let four = BlsScalar::from(4);

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = evaluations.a_next_eval - four * evaluations.a_eval;
        let c_0 = delta(a);

        let b = evaluations.b_next_eval - four * evaluations.b_eval;
        let c_1 = delta(b) * kappa;

        let d = evaluations.d_next_eval - four * evaluations.d_eval;
        let c_2 = delta(d) * kappa_sq;

        let w = evaluations.c_eval;
        let c_3 = (w - a * b) * kappa_cu;

        let c_4 = delta_xor_and(&a, &b, &w, &d, &evaluations.q_c_eval) * kappa_qu;
        scalars.push((c_0 + c_1 + c_2 + c_3 + c_4) * logic_separation_challenge);
        points.push(self.q_logic.0);
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PlookupVerifierKey {
    pub q_c: Commitment,
    pub q_logic: Commitment,
}

impl PlookupVerifierKey {
    pub(crate) fn compute_linearisation_commitment(
        &self,
        logic_separation_challenge: &BlsScalar,
        scalars: &mut Vec<BlsScalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &PlookupProofEvaluations,
    ) {
        let four = BlsScalar::from(4);

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a = evaluations.a_next_eval - four * evaluations.a_eval;
        let c_0 = delta(a);

        let b = evaluations.b_next_eval - four * evaluations.b_eval;
        let c_1 = delta(b) * kappa;

        let d = evaluations.d_next_eval - four * evaluations.d_eval;
        let c_2 = delta(d) * kappa_sq;

        let w = evaluations.c_eval;
        let c_3 = (w - a * b) * kappa_cu;

        let c_4 = delta_xor_and(&a, &b, &w, &d, &evaluations.q_c_eval) * kappa_qu;
        scalars.push((c_0 + c_1 + c_2 + c_3 + c_4) * logic_separation_challenge);
        points.push(self.q_logic.0);
    }
}
