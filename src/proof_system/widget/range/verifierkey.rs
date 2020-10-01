// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::delta;
use crate::commitment_scheme::kzg10::Commitment;
use crate::proof_system::linearisation_poly::ProofEvaluations;
use dusk_bls12_381::{G1Affine, Scalar};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct VerifierKey {
    pub q_range: Commitment,
}

impl VerifierKey {
    pub(crate) fn compute_linearisation_commitment(
        &self,
        range_separation_challenge: &Scalar,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let four = Scalar::from(4);

        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let b_1 = delta(evaluations.c_eval - (four * evaluations.d_eval));
        let b_2 = delta(evaluations.b_eval - four * evaluations.c_eval) * kappa;
        let b_3 = delta(evaluations.a_eval - four * evaluations.b_eval) * kappa_sq;
        let b_4 = delta(evaluations.d_next_eval - (four * evaluations.a_eval)) * kappa_cu;

        scalars.push((b_1 + b_2 + b_3 + b_4) * range_separation_challenge);
        points.push(self.q_range.0);
    }
}
