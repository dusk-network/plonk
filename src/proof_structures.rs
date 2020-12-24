// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::{BlsScalar, G1Affine, G1Projective};

#[cfg(feature = "std")]
use anyhow::{Error, Result};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Holds a commitment to a polynomial in a form of a `G1Affine` Bls12_381 point.
pub struct Commitment(
    /// The commitment is a group element.
    pub G1Affine,
);

impl Commitment {
    /// Builds a `Commitment` from a Bls12_381 `G1Projective` point.
    pub fn from_projective(g: G1Projective) -> Self {
        Self(g.into())
    }
    /// Builds a `Commitment` from a Bls12_381 `G1Affine` point.
    pub fn from_affine(g: G1Affine) -> Self {
        Self(g)
    }
    /// Builds an empty `Commitment` which is equivalent to the
    /// `G1Affine` identity point in Bls12_381.
    pub fn empty() -> Self {
        Commitment(G1Affine::identity())
    }
}

impl Default for Commitment {
    fn default() -> Self {
        Commitment::empty()
    }
}

/// Proof Evaluations is a subset of all of the evaluations. These evaluations will be added to the proof
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ProofEvaluations {
    /// Evaluation of the witness polynomial for the left wire at `z`
    pub a_eval: BlsScalar,
    /// Evaluation of the witness polynomial for the right wire at `z`
    pub b_eval: BlsScalar,
    /// Evaluation of the witness polynomial for the output wire at `z`
    pub c_eval: BlsScalar,
    /// Evaluation of the witness polynomial for the fourth wire at `z`
    pub d_eval: BlsScalar,
    /// A eval
    pub a_next_eval: BlsScalar,
    /// Next eval
    pub b_next_eval: BlsScalar,
    /// Evaluation of the witness polynomial for the fourth wire at `z * root of unity`
    pub d_next_eval: BlsScalar,
    /// Evaluation of the arithmetic selector polynomial at `z`
    pub q_arith_eval: BlsScalar,
    /// C eval
    pub q_c_eval: BlsScalar,
    /// Left eval
    pub q_l_eval: BlsScalar,
    /// Right eval
    pub q_r_eval: BlsScalar,
    /// Evaluation of the left sigma polynomial at `z`
    pub left_sigma_eval: BlsScalar,
    /// Evaluation of the right sigma polynomial at `z`
    pub right_sigma_eval: BlsScalar,
    /// Evaluation of the out sigma polynomial at `z`
    pub out_sigma_eval: BlsScalar,

    /// Evaluation of the linearisation sigma polynomial at `z`
    pub lin_poly_eval: BlsScalar,

    /// (Shifted) Evaluation of the permutation polynomial at `z * root of unity`
    pub perm_eval: BlsScalar,
}

impl ProofEvaluations {
    /// Serialises a Proof Evaluation struct to bytes
    pub fn to_bytes(&self) -> [u8; ProofEvaluations::serialized_size()] {
        let mut bytes = [0u8; ProofEvaluations::serialized_size()];

        bytes[0..32].copy_from_slice(&self.a_eval.to_bytes()[..]);
        bytes[32..64].copy_from_slice(&self.b_eval.to_bytes()[..]);
        bytes[64..96].copy_from_slice(&self.c_eval.to_bytes()[..]);
        bytes[96..128].copy_from_slice(&self.d_eval.to_bytes()[..]);
        bytes[128..160].copy_from_slice(&self.a_next_eval.to_bytes()[..]);
        bytes[160..192].copy_from_slice(&self.b_next_eval.to_bytes()[..]);
        bytes[192..224].copy_from_slice(&self.d_next_eval.to_bytes()[..]);
        bytes[224..256].copy_from_slice(&self.q_arith_eval.to_bytes()[..]);
        bytes[256..288].copy_from_slice(&self.q_c_eval.to_bytes()[..]);
        bytes[288..320].copy_from_slice(&self.q_l_eval.to_bytes()[..]);
        bytes[320..352].copy_from_slice(&self.q_r_eval.to_bytes()[..]);
        bytes[352..384].copy_from_slice(&self.left_sigma_eval.to_bytes()[..]);
        bytes[384..416].copy_from_slice(&self.right_sigma_eval.to_bytes()[..]);
        bytes[416..448].copy_from_slice(&self.out_sigma_eval.to_bytes()[..]);
        bytes[448..480].copy_from_slice(&self.lin_poly_eval.to_bytes()[..]);
        bytes[480..512].copy_from_slice(&self.perm_eval.to_bytes()[..]);

        bytes
    }

    /// Deserialises a slice of bytes into a proof Evaluation struct
    #[cfg(feature = "std")]
    pub fn from_bytes(bytes: &[u8]) -> Result<ProofEvaluations, Error> {
        use crate::serialisation::{read_scalar, SerialisationErrors};

        if bytes.len() != ProofEvaluations::serialized_size() {
            return Err(SerialisationErrors::NotEnoughBytes.into());
        }

        let (a_eval, rest) = read_scalar(bytes)?;
        let (b_eval, rest) = read_scalar(rest)?;
        let (c_eval, rest) = read_scalar(rest)?;
        let (d_eval, rest) = read_scalar(rest)?;
        let (a_next_eval, rest) = read_scalar(rest)?;
        let (b_next_eval, rest) = read_scalar(rest)?;
        let (d_next_eval, rest) = read_scalar(rest)?;
        let (q_arith_eval, rest) = read_scalar(rest)?;
        let (q_c_eval, rest) = read_scalar(rest)?;
        let (q_l_eval, rest) = read_scalar(rest)?;
        let (q_r_eval, rest) = read_scalar(rest)?;
        let (left_sigma_eval, rest) = read_scalar(rest)?;
        let (right_sigma_eval, rest) = read_scalar(rest)?;
        let (out_sigma_eval, rest) = read_scalar(rest)?;
        let (lin_poly_eval, rest) = read_scalar(rest)?;
        let (perm_eval, _) = read_scalar(rest)?;

        let proof_evals = ProofEvaluations {
            a_eval,
            b_eval,
            c_eval,
            d_eval,
            a_next_eval,
            b_next_eval,
            d_next_eval,
            q_arith_eval,
            q_c_eval,
            q_l_eval,
            q_r_eval,
            left_sigma_eval,
            right_sigma_eval,
            out_sigma_eval,
            lin_poly_eval,
            perm_eval,
        };

        Ok(proof_evals)
    }

    /// Serialized side of the structure
    pub const fn serialized_size() -> usize {
        const NUM_SCALARS: usize = 16;
        const SCALAR_SIZE: usize = 32;

        NUM_SCALARS * SCALAR_SIZE
    }
}

/// A Proof is a composition of `Commitments` to the witness, permutation,
/// quotient, shifted and opening polynomials as well as the
/// `ProofEvaluations`.
///
/// It's main goal is to have a `verify()` method attached which contains the
/// logic of the operations that the `Verifier` will need to do in order to
/// formally verify the `Proof`.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Proof {
    /// Commitment to the witness polynomial for the left wires.
    pub a_comm: Commitment,
    /// Commitment to the witness polynomial for the right wires.
    pub b_comm: Commitment,
    /// Commitment to the witness polynomial for the output wires.
    pub c_comm: Commitment,
    /// Commitment to the witness polynomial for the fourth wires.
    pub d_comm: Commitment,

    /// Commitment to the permutation polynomial.
    pub z_comm: Commitment,

    /// Commitment to the quotient polynomial.
    pub t_1_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_2_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_3_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_4_comm: Commitment,

    /// Commitment to the opening polynomial.
    pub w_z_comm: Commitment,
    /// Commitment to the shifted opening polynomial.
    pub w_zw_comm: Commitment,
    /// Subset of all of the evaluations added to the proof.
    pub evaluations: ProofEvaluations,
}
