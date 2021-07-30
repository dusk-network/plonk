// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::kzg10::Commitment;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) struct VerifierKey {
    pub(crate) q_variable_group_add: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearisation_poly::ProofEvaluations;
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{BlsScalar, G1Affine};
    use dusk_jubjub::EDWARDS_D;

    impl VerifierKey {
        pub(crate) fn compute_linearisation_commitment(
            &self,
            curve_add_separation_challenge: &BlsScalar,
            scalars: &mut Vec<BlsScalar>,
            points: &mut Vec<G1Affine>,
            evaluations: &ProofEvaluations,
        ) {
            let kappa = curve_add_separation_challenge.square();

            let x_1 = evaluations.a_eval;
            let x_3 = evaluations.a_next_eval;
            let y_1 = evaluations.b_eval;
            let y_3 = evaluations.b_next_eval;
            let x_2 = evaluations.c_eval;
            let y_2 = evaluations.d_eval;
            let x1_y2 = evaluations.d_next_eval;

            // Checks
            //
            // Check x1 * y2 is correct
            let xy_consistency = x_1 * y_2 - x1_y2;

            let y1_x2 = y_1 * x_2;
            let y1_y2 = y_1 * y_2;
            let x1_x2 = x_1 * x_2;

            // Check x_3 is correct
            let x3_lhs = x1_y2 + y1_x2;
            let x3_rhs = x_3 + (x_3 * (EDWARDS_D * x1_y2 * y1_x2));
            let x3_consistency = (x3_lhs - x3_rhs) * kappa;

            // Check y_3 is correct
            let y3_lhs = y1_y2 + x1_x2;
            let y3_rhs = y_3 - (y_3 * EDWARDS_D * x1_y2 * y1_x2);
            let y3_consistency = (y3_lhs - y3_rhs) * kappa.square();

            let identity = xy_consistency + x3_consistency + y3_consistency;

            scalars.push(identity * curve_add_separation_challenge);
            points.push(self.q_variable_group_add.0);
        }
    }
}
