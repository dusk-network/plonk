// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::{Evaluations, Polynomial};
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::EDWARDS_D;

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct ProverKey {
    pub(crate) q_variable_group_add: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        curve_add_separation_challenge: &BlsScalar,
        w_l_i: &BlsScalar,      // x_1
        w_l_i_next: &BlsScalar, // x_3
        w_r_i: &BlsScalar,      // y_1
        w_r_i_next: &BlsScalar, // y_3
        w_o_i: &BlsScalar,      // x_2
        w_4_i: &BlsScalar,      // y_2
        w_4_i_next: &BlsScalar, // x_1 * y_2
    ) -> BlsScalar {
        let q_variable_group_add_i = &self.q_variable_group_add.1[index];

        let kappa = curve_add_separation_challenge.square();

        let x_1 = w_l_i;
        let x_3 = w_l_i_next;
        let y_1 = w_r_i;
        let y_3 = w_r_i_next;
        let x_2 = w_o_i;
        let y_2 = w_4_i;
        let x1_y2 = w_4_i_next;

        // Checks
        //
        // Check x1 * y2 is correct
        let xy_consistency = x_1 * y_2 - x1_y2;

        let y1_x2 = y_1 * x_2;
        let y1_y2 = y_1 * y_2;
        let x1_x2 = x_1 * x_2;

        // Check x_3 is correct
        let x3_lhs = x1_y2 + y1_x2;
        let x3_rhs = x_3 + (x_3 * EDWARDS_D * x1_y2 * y1_x2);
        let x3_consistency = (x3_lhs - x3_rhs) * kappa;

        // // Check y_3 is correct
        let y3_lhs = y1_y2 + x1_x2;
        let y3_rhs = y_3 - y_3 * EDWARDS_D * x1_y2 * y1_x2;
        let y3_consistency = (y3_lhs - y3_rhs) * kappa.square();

        let identity = xy_consistency + x3_consistency + y3_consistency;

        identity * q_variable_group_add_i * curve_add_separation_challenge
    }

    pub(crate) fn compute_linearisation(
        &self,
        curve_add_separation_challenge: &BlsScalar,
        a_eval: &BlsScalar,
        a_next_eval: &BlsScalar,
        b_eval: &BlsScalar,
        b_next_eval: &BlsScalar,
        c_eval: &BlsScalar,
        d_eval: &BlsScalar,
        d_next_eval: &BlsScalar,
    ) -> Polynomial {
        let q_variable_group_add_poly = &self.q_variable_group_add.0;

        let kappa = curve_add_separation_challenge.square();

        let x_1 = a_eval;
        let x_3 = a_next_eval;
        let y_1 = b_eval;
        let y_3 = b_next_eval;
        let x_2 = c_eval;
        let y_2 = d_eval;
        let x1_y2 = d_next_eval;

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
        let y3_rhs = y_3 - y_3 * EDWARDS_D * x1_y2 * y1_x2;
        let y3_consistency = (y3_lhs - y3_rhs) * kappa.square();

        let identity = xy_consistency + x3_consistency + y3_consistency;

        q_variable_group_add_poly * &(identity * curve_add_separation_challenge)
    }
}
