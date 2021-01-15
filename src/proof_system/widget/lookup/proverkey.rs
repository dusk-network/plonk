// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::compress;
use crate::fft::{Evaluations, Polynomial};

use dusk_bls12_381::BlsScalar;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ProverKey {
    pub q_lookup: (Polynomial, Evaluations),
}

impl ProverKey {
    /// Compute identity check for lookup gates
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        lookup_separation_challenge: &BlsScalar,
        w_l_i: &BlsScalar,
        w_r_i: &BlsScalar,
        w_o_i: &BlsScalar,
        w_4_i: &BlsScalar,
        compressed_f_element: &BlsScalar,
        zeta: &BlsScalar,
    ) -> BlsScalar {
        // This function will check the identity
        //
        // q_lookup(X) * (a(X) + zeta * b(X) + (zeta^2 * c(X)) + (zeta^3 * d(X) - f(X)))

        let q_lookup_i = self.q_lookup.1[index];

        let compressed_tuple = compress(*w_l_i, *w_r_i, *w_o_i, *w_4_i, *zeta);

        q_lookup_i * (compressed_tuple - compressed_f_element) * lookup_separation_challenge
    }

    /// Compute linearisation for lookup gates
    pub(crate) fn compute_linearisation(
        &self,
        lookup_separation_challenge: &BlsScalar,
        f_eval: &BlsScalar,
    ) -> Polynomial {
        // q_lookup(X) * f_eval * alpha^3
        let q_lookup_poly = &self.q_lookup.0;

        let a = f_eval * lookup_separation_challenge;

        let b = q_lookup_poly * &a;

        -b
    }
}
