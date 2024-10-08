// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::Commitment;
use dusk_bytes::{DeserializableSlice, Serializable};

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
    pub q_m: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_l: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_r: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_o: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_f: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_c: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_arith: Commitment,
}

impl Serializable<{ 7 * Commitment::SIZE }> for VerifierKey {
    type Error = dusk_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;
        let mut buff = [0u8; Self::SIZE];
        let mut writer = &mut buff[..];
        writer.write(&self.q_m.to_bytes());
        writer.write(&self.q_l.to_bytes());
        writer.write(&self.q_r.to_bytes());
        writer.write(&self.q_o.to_bytes());
        writer.write(&self.q_f.to_bytes());
        writer.write(&self.q_c.to_bytes());
        writer.write(&self.q_arith.to_bytes());

        buff
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<VerifierKey, Self::Error> {
        let mut buffer = &buf[..];
        let q_m = Commitment::from_reader(&mut buffer)?;
        let q_l = Commitment::from_reader(&mut buffer)?;
        let q_r = Commitment::from_reader(&mut buffer)?;
        let q_o = Commitment::from_reader(&mut buffer)?;
        let q_f = Commitment::from_reader(&mut buffer)?;
        let q_c = Commitment::from_reader(&mut buffer)?;
        let q_arith = Commitment::from_reader(&mut buffer)?;

        Ok(VerifierKey {
            q_m,
            q_l,
            q_r,
            q_o,
            q_f,
            q_c,
            q_arith,
        })
    }
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearization_poly::ProofEvaluations;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{BlsScalar, G1Affine};

    impl VerifierKey {
        pub(crate) fn compute_linearization_commitment(
            &self,
            scalars: &mut Vec<BlsScalar>,
            points: &mut Vec<G1Affine>,
            evaluations: &ProofEvaluations,
        ) {
            let q_arith_eval = evaluations.q_arith_eval;

            scalars
                .push(evaluations.a_eval * evaluations.b_eval * q_arith_eval);
            points.push(self.q_m.0);

            scalars.push(evaluations.a_eval * q_arith_eval);
            points.push(self.q_l.0);

            scalars.push(evaluations.b_eval * q_arith_eval);
            points.push(self.q_r.0);

            scalars.push(evaluations.c_eval * q_arith_eval);
            points.push(self.q_o.0);

            scalars.push(evaluations.d_eval * q_arith_eval);
            points.push(self.q_f.0);

            scalars.push(q_arith_eval);
            points.push(self.q_c.0);
        }
    }
}
