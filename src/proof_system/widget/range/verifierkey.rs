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
    pub(crate) q_range: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearization_poly::ProofEvaluations;
    use crate::proof_system::widget::range::proverkey::delta;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use zero_bls12_381::{Fr as BlsScalar, G1Affine};
    use zero_crypto::behave::PrimeField;

    impl VerifierKey {
        pub(crate) fn compute_linearization_commitment(
            &self,
            range_separation_challenge: &BlsScalar,
            scalars: &mut Vec<BlsScalar>,
            points: &mut Vec<G1Affine>,
            evaluations: &ProofEvaluations,
        ) {
            let four = BlsScalar::from(4);

            let kappa = range_separation_challenge.square();
            let kappa_sq = kappa.square();
            let kappa_cu = kappa_sq * kappa;

            let b_1 = delta(evaluations.c_eval - (four * evaluations.d_eval));
            let b_2 =
                delta(evaluations.b_eval - four * evaluations.c_eval) * kappa;
            let b_3 = delta(evaluations.a_eval - four * evaluations.b_eval)
                * kappa_sq;
            let b_4 =
                delta(evaluations.d_next_eval - (four * evaluations.a_eval))
                    * kappa_cu;

            scalars.push((b_1 + b_2 + b_3 + b_4) * range_separation_challenge);
            points.push(self.q_range.0);
        }
    }
}
