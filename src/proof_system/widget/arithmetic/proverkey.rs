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
    pub q_m: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_l: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_r: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_o: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_f: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_c: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_arith: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
    ) -> BlsScalar {
        let q_m_i = &self.q_m.1[index];
        let q_l_i = &self.q_l.1[index];
        let q_r_i = &self.q_r.1[index];
        let q_o_i = &self.q_o.1[index];
        let q_f_i = &self.q_f.1[index];
        let q_c_i = &self.q_c.1[index];
        let q_arith_i = &self.q_arith.1[index];

        // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + d(x)q_F(X) +
        // q_C(X)) * q_arith(X)
        //
        let a_1 = a_i * b_i * q_m_i;
        let a_2 = a_i * q_l_i;
        let a_3 = b_i * q_r_i;
        let a_4 = c_i * q_o_i;
        let a_5 = d_i * q_f_i;
        let a_6 = q_c_i;
        (a_1 + a_2 + a_3 + a_4 + a_5 + a_6) * q_arith_i
    }

    pub(crate) fn compute_linearization(
        &self,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let q_m_poly = &self.q_m.0;
        let q_l_poly = &self.q_l.0;
        let q_r_poly = &self.q_r.0;
        let q_o_poly = &self.q_o.0;
        let q_f_poly = &self.q_f.0;
        let q_c_poly = &self.q_c.0;

        // (a_eval * b_eval * q_m_poly + a_eval * q_l + b_eval * q_r + c_eval
        // * q_o + d_eval * q_f + q_c) * q_arith_eval
        //
        // a_eval * b_eval * q_m_poly
        let ab = evaluations.a_eval * evaluations.b_eval;
        let a_0 = q_m_poly * &ab;

        // a_eval * q_l
        let a_1 = q_l_poly * &evaluations.a_eval;

        // b_eval * q_r
        let a_2 = q_r_poly * &evaluations.b_eval;

        //c_eval * q_o
        let a_3 = q_o_poly * &evaluations.c_eval;

        // d_eval * q_f
        let a_4 = q_f_poly * &evaluations.d_eval;

        let mut a = &a_0 + &a_1;
        a = &a + &a_2;
        a = &a + &a_3;
        a = &a + &a_4;
        a = &a + q_c_poly;
        a = &a * &evaluations.q_arith_eval;

        a
    }
}
