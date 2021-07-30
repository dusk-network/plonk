// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::kzg10::Commitment;
use dusk_bytes::{DeserializableSlice, Serializable};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) struct VerifierKey {
    pub q_m: Commitment,
    pub q_l: Commitment,
    pub q_r: Commitment,
    pub q_o: Commitment,
    pub q_4: Commitment,
    pub q_c: Commitment,
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
        writer.write(&self.q_c.to_bytes());
        writer.write(&self.q_4.to_bytes());
        writer.write(&self.q_arith.to_bytes());

        buff
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<VerifierKey, Self::Error> {
        let mut buffer = &buf[..];
        let q_m = Commitment::from_reader(&mut buffer)?;
        let q_l = Commitment::from_reader(&mut buffer)?;
        let q_r = Commitment::from_reader(&mut buffer)?;
        let q_o = Commitment::from_reader(&mut buffer)?;
        let q_c = Commitment::from_reader(&mut buffer)?;
        let q_4 = Commitment::from_reader(&mut buffer)?;
        let q_arith = Commitment::from_reader(&mut buffer)?;

        Ok(VerifierKey {
            q_m,
            q_l,
            q_r,
            q_o,
            q_4,
            q_c,
            q_arith,
        })
    }
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearisation_poly::ProofEvaluations;
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{BlsScalar, G1Affine};

    impl VerifierKey {
        pub(crate) fn compute_linearisation_commitment(
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
            points.push(self.q_4.0);

            scalars.push(q_arith_eval);
            points.push(self.q_c.0);
        }
    }
}
