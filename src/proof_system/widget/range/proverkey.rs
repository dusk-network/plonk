// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
use dusk_bls12_381::BlsScalar;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Serialize,
    ser::{ScratchSpace, Serializer},
};

use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearization_poly::ProofEvaluations;

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

#[derive(Clone, Copy)]
pub(crate) struct RangeChallenges {
    challenge: BlsScalar,
    kappa: BlsScalar,
    kappa_sq: BlsScalar,
    kappa_cu: BlsScalar,
}

impl RangeChallenges {
    pub(crate) fn new(range_separation_challenge: &BlsScalar) -> Self {
        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        Self {
            challenge: *range_separation_challenge,
            kappa,
            kappa_sq,
            kappa_cu,
        }
    }
}

impl ProverKey {
    #[inline]
    pub(crate) fn compute_quotient_i_with_challenges(
        &self,
        index: usize,
        challenges: &RangeChallenges,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        d_i_w: &BlsScalar,
    ) -> BlsScalar {
        let q_range_i = &self.q_range.1[index];
        if *q_range_i == BlsScalar::zero() {
            return BlsScalar::zero();
        }

        // Delta([o(X) - 4 * d(X)]) + Delta([b(X) - 4 * o(X)]) + Delta([a(X) - 4
        // * b(X)]) + Delta([d(Xg) - 4 * a(X)]) * Q_Range(X)
        //
        let b_1 = delta(c_i - d_i.double().double());
        let b_2 = delta(b_i - c_i.double().double()) * challenges.kappa;
        let b_3 = delta(a_i - b_i.double().double()) * challenges.kappa_sq;
        let b_4 = delta(d_i_w - a_i.double().double()) * challenges.kappa_cu;
        (b_1 + b_2 + b_3 + b_4) * q_range_i * challenges.challenge
    }

    pub(crate) fn linearization_scalar(
        range_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> BlsScalar {
        let four = BlsScalar::from(4);

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

        (b_1 + b_2 + b_3 + b_4) * range_separation_challenge
    }
}

// Computes f(f-1)(f-2)(f-3)
#[inline]
pub(crate) fn delta(f: BlsScalar) -> BlsScalar {
    let one = BlsScalar::one();
    let f_1 = f - one;
    let f_2 = f_1 - one;
    let f_3 = f_2 - one;
    f * f_1 * f_2 * f_3
}
