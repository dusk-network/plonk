// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! KZG10 Proof module.

use super::Commitment;
use crate::transcript::TranscriptProtocol;
use crate::util::powers_of;
use alloc::vec::Vec;
use dusk_bls12_381::{BlsScalar, G1Projective};
use merlin::Transcript;

#[derive(Copy, Clone, Debug)]
/// Proof that a polynomial `p` was correctly evaluated at a point `z`
/// producing the evaluated point p(z).
pub(crate) struct Proof {
    /// This is a commitment to the witness polynomial.
    pub(crate) commitment_to_witness: Commitment,
    /// This is the result of evaluating a polynomial at the point `z`.
    pub(crate) evaluated_point: BlsScalar,
    /// This is the commitment to the polynomial that you want to prove a
    /// statement about.
    pub(crate) commitment_to_polynomial: Commitment,
}

/// Proof that multiple polynomials were correctly evaluated at a point `z`,
/// each producing their respective evaluated points p_i(z).
#[derive(Debug)]
pub(crate) struct AggregateProof {
    /// This is a commitment to the aggregated witness polynomial.
    commitment_to_witness: Commitment,
    /// These are the results of the evaluating each polynomial at the point
    /// `z`.
    evaluated_points: Vec<BlsScalar>,
    /// These are the commitments to the polynomials which you want to prove a
    /// statement about.
    commitments_to_polynomials: Vec<Commitment>,
}

impl AggregateProof {
    /// Initialises an `AggregatedProof` with the commitment to the witness.
    pub(crate) fn with_witness(witness: Commitment) -> AggregateProof {
        AggregateProof {
            commitment_to_witness: witness,
            evaluated_points: Vec::new(),
            commitments_to_polynomials: Vec::new(),
        }
    }

    /// Adds an evaluated point with the commitment to the polynomial which
    /// produced it.
    pub(crate) fn add_part(&mut self, part: (BlsScalar, Commitment)) {
        self.evaluated_points.push(part.0);
        self.commitments_to_polynomials.push(part.1);
    }

    /// Flattens an `AggregateProof` into a `Proof`.
    /// The transcript must have the same view as the transcript that was used
    /// to aggregate the witness in the proving stage.
    pub(crate) fn flatten(&self, transcript: &mut Transcript) -> Proof {
        let challenge = transcript.challenge_scalar(b"aggregate_witness");
        let powers =
            powers_of(&challenge, self.commitments_to_polynomials.len() - 1);

        // Flattened polynomial commitments using challenge
        let flattened_poly_commitments: G1Projective = self
            .commitments_to_polynomials
            .iter()
            .zip(powers.iter())
            .map(|(poly, challenge)| poly.0 * challenge)
            .sum();
        // Flattened evaluation points
        let flattened_poly_evaluations: BlsScalar = self
            .evaluated_points
            .iter()
            .zip(powers.iter())
            .map(|(eval, challenge)| eval * challenge)
            .fold(BlsScalar::zero(), |acc, current_val| acc + current_val);

        Proof {
            commitment_to_witness: self.commitment_to_witness,
            evaluated_point: flattened_poly_evaluations,
            commitment_to_polynomial: Commitment::from_projective(
                flattened_poly_commitments,
            ),
        }
    }
}
