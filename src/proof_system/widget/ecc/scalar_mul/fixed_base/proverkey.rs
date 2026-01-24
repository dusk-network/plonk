// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearization_poly::ProofEvaluations;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::EDWARDS_D;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Serialize,
    ser::{ScratchSpace, Serializer},
};

#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct ProverKey {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_l: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_r: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_c: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_fixed_group_add: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        ecc_separation_challenge: &BlsScalar,
        a_i: &BlsScalar,   // acc_x or curr_x
        a_i_w: &BlsScalar, // shifted x
        b_i: &BlsScalar,   // acc_y or curr_y
        b_i_w: &BlsScalar, // shifted y
        c_i: &BlsScalar,   // xy_alpha
        d_i: &BlsScalar,   // accumulated_bit
        d_i_w: &BlsScalar, // accumulated_bit_w
    ) -> BlsScalar {
        let q_fixed_group_add_i = &self.q_fixed_group_add.1[index];
        let q_c_i = &self.q_c.1[index];

        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let x_beta = &self.q_l.1[index];
        let y_beta = &self.q_r.1[index];

        let acc_x = a_i;
        let acc_x_w = a_i_w;
        let acc_y = b_i;
        let acc_y_w = b_i_w;

        let xy_alpha = c_i;

        let accumulated_bit = d_i;
        let accumulated_bit_w = d_i_w;
        let bit = extract_bit(accumulated_bit, accumulated_bit_w);

        // Checks
        //
        // Check bit consistency
        let bit_consistency = check_bit_consistency(bit);

        // Derive y_alpha and x_alpha from bit
        let y_alpha =
            bit.square() * (y_beta - BlsScalar::one()) + BlsScalar::one();
        let x_alpha = bit * x_beta;

        // xy_alpha consistency check
        let xy_consistency = ((bit * q_c_i) - xy_alpha) * kappa;

        // x accumulator consistency check
        let x_3 = acc_x_w;
        let lhs = x_3 + (x_3 * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let rhs = (acc_x * y_alpha) + (acc_y * x_alpha);
        let x_acc_consistency = (lhs - rhs) * kappa_sq;

        // y accumulator consistency check
        let y_3 = acc_y_w;
        let lhs = y_3 - (y_3 * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let rhs = (acc_y * y_alpha) + (acc_x * x_alpha);
        let y_acc_consistency = (lhs - rhs) * kappa_cu;

        let identity = bit_consistency
            + x_acc_consistency
            + y_acc_consistency
            + xy_consistency;

        identity * q_fixed_group_add_i * ecc_separation_challenge
    }

    pub(crate) fn compute_linearization(
        &self,
        ecc_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let q_fixed_group_add_poly = &self.q_fixed_group_add.0;

        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let x_beta_eval = evaluations.q_l_eval;
        let y_beta_eval = evaluations.q_r_eval;

        let acc_x = evaluations.a_eval;
        let acc_x_w = evaluations.a_w_eval;
        let acc_y = evaluations.b_eval;
        let acc_y_w = evaluations.b_w_eval;

        let xy_alpha = evaluations.c_eval;

        let accumulated_bit = evaluations.d_eval;
        let accumulated_bit_w = evaluations.d_w_eval;
        let bit = extract_bit(&accumulated_bit, &accumulated_bit_w);

        // Check bit consistency
        let bit_consistency = check_bit_consistency(bit);

        let y_alpha =
            bit.square() * (y_beta_eval - BlsScalar::one()) + BlsScalar::one();

        let x_alpha = x_beta_eval * bit;

        // xy_alpha consistency check
        let xy_consistency = ((bit * evaluations.q_c_eval) - xy_alpha) * kappa;

        // x accumulator consistency check
        let x_3 = acc_x_w;
        let lhs = x_3 + (x_3 * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let rhs = (x_alpha * acc_y) + (y_alpha * acc_x);
        let x_acc_consistency = (lhs - rhs) * kappa_sq;

        // y accumulator consistency check
        let y_3 = acc_y_w;
        let lhs = y_3 - (y_3 * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let rhs = (x_alpha * acc_x) + (y_alpha * acc_y);
        let y_acc_consistency = (lhs - rhs) * kappa_cu;

        let a = bit_consistency
            + x_acc_consistency
            + y_acc_consistency
            + xy_consistency;

        q_fixed_group_add_poly * &(a * ecc_separation_challenge)
    }
}

pub(crate) fn extract_bit(acc: &BlsScalar, acc_w: &BlsScalar) -> BlsScalar {
    // acc_w - 2 * acc
    acc_w - acc - acc
}

// Ensures that the bit is either +1, -1 or 0
pub(crate) fn check_bit_consistency(bit: BlsScalar) -> BlsScalar {
    let one = BlsScalar::one();
    bit * (bit - one) * (bit + one)
}
