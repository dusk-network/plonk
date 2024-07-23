// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearization_poly::ProofEvaluations;
use dusk_bls12_381::BlsScalar;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
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
    pub(crate) q_range: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        range_separation_challenge: &BlsScalar,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        d_i_w: &BlsScalar,
    ) -> BlsScalar {
        let four = BlsScalar::from(4);
        let q_range_i = &self.q_range.1[index];

        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        // Delta([o(X) - 4 * d(X)]) + Delta([b(X) - 4 * o(X)]) + Delta([a(X) - 4
        // * b(X)]) + Delta([d(Xg) - 4 * a(X)]) * Q_Range(X)
        //
        let b_1 = delta(c_i - four * d_i);
        let b_2 = delta(b_i - four * c_i) * kappa;
        let b_3 = delta(a_i - four * b_i) * kappa_sq;
        let b_4 = delta(d_i_w - four * a_i) * kappa_cu;
        (b_1 + b_2 + b_3 + b_4) * q_range_i * range_separation_challenge
    }

    pub(crate) fn compute_linearization(
        &self,
        range_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let four = BlsScalar::from(4);
        let q_range_poly = &self.q_range.0;

        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        // Delta([c_eval - 4 * d_eval]) + Delta([b_eval - 4 * c_eval]) +
        // Delta([a_eval - 4 * b_eval]) + Delta([d_w_eval - 4 * a_eval]) *
        // Q_Range(X)
        let b_1 = delta(evaluations.c_eval - four * evaluations.d_eval);
        let b_2 = delta(evaluations.b_eval - four * evaluations.c_eval) * kappa;
        let b_3 =
            delta(evaluations.a_eval - four * evaluations.b_eval) * kappa_sq;
        let b_4 =
            delta(evaluations.d_w_eval - four * evaluations.a_eval) * kappa_cu;

        let t = (b_1 + b_2 + b_3 + b_4) * range_separation_challenge;

        q_range_poly * &t
    }
}

// Computes f(f-1)(f-2)(f-3)
pub(crate) fn delta(f: BlsScalar) -> BlsScalar {
    let f_1 = f - BlsScalar::one();
    let f_2 = f - BlsScalar::from(2);
    let f_3 = f - BlsScalar::from(3);
    f * f_1 * f_2 * f_3
}
