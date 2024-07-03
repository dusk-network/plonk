// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::Commitment;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct VerifierKey {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_c: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_logic: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearization_poly::ProofEvaluations;
    use crate::proof_system::widget::logic::proverkey::{delta, delta_xor_and};
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{BlsScalar, G1Affine};

    impl VerifierKey {
        pub(crate) fn compute_linearization_commitment(
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
            let o_0 = delta(a);

            let b = evaluations.b_next_eval - four * evaluations.b_eval;
            let o_1 = delta(b) * kappa;

            let d = evaluations.d_next_eval - four * evaluations.d_eval;
            let o_2 = delta(d) * kappa_sq;

            let o = evaluations.c_eval;
            let o_3 = (o - a * b) * kappa_cu;

            let o_4 =
                delta_xor_and(&a, &b, &o, &d, &evaluations.q_c_eval) * kappa_qu;
            scalars.push(
                (o_0 + o_1 + o_2 + o_3 + o_4) * logic_separation_challenge,
            );
            points.push(self.q_logic.0);
        }
    }
}
