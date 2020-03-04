use bls12_381::{G1Affine, G1Projective, Scalar};
// Code was taken and modified from Pratyush: https://github.com/scipr-lab/poly-commit/blob/master/src/kzg10/mod.rs
pub mod errors;
pub mod key;
pub mod srs;
use crate::transcript::TranscriptProtocol;

use crate::util::powers_of;
pub use key::{ProverKey, VerifierKey};
pub use srs::SRS;
#[derive(Copy, Clone, Debug)]
pub struct Proof {
    /// This is a commitment to the witness polynomial `w`
    /// w = p(x) - p(z) / x - z
    pub commitment_to_witness: Commitment,
    /// This is the evaluation `y` of the committed polynomial
    /// y = p(z)
    pub evaluated_point: Scalar,
    /// These is the commitment to the polynomial that you want to prove a statement about
    pub commitment_to_polynomial: Commitment,
    // This is the evaluated_point `z` of the committed polynomial
    // y = p(z)
    // pub evaluation_point: Scalar,
}

/// Due to KZG10 being homomorphic, we can supply a single witness commitment
/// for multiple polynomials at the same point
pub struct AggregateProof {
    /// This is a commitment to the witness polynomial `w`
    /// w is a witness for multiple polynomials
    pub commitment_to_witness: Commitment,
    /// This is the evaluations `y` of the committed polynomials
    pub evaluated_points: Vec<Scalar>,
    /// These are the commitments to the polynomials that you want to prove a statement about
    pub commitments_to_polynomials: Vec<Commitment>,
    // This is the evaluated_point `z` that all of the polynomials are evaluated at
    // pub evaluation_point: Scalar,
}

impl AggregateProof {
    /// Creates an `AggregatedProof` with the commitment to the witness
    pub fn with_witness(witness: Commitment) -> AggregateProof {
        AggregateProof {
            commitment_to_witness: witness,
            evaluated_points: Vec::new(),
            commitments_to_polynomials: Vec::new(),
        }
    }
    // Flattens an aggregate proof into a `Proof`
    // The challenge must be the same challenge that was used to aggregate the witness
    pub fn flatten(&self, transcript: &mut dyn TranscriptProtocol) -> Proof {
        let challenge = transcript.challenge_scalar(b"");
        let powers = powers_of(&challenge, self.commitments_to_polynomials.len());

        // Flattened polynomial commitments using challenge
        let flattened_poly_commitments: G1Projective = self
            .commitments_to_polynomials
            .iter()
            .zip(powers.iter())
            .map(|(poly, challenge)| poly.0 * challenge)
            .sum();
        // Flattened evaluation points
        let flattened_poly_evaluations: Scalar = self
            .evaluated_points
            .iter()
            .zip(powers.iter())
            .map(|(eval, challenge)| eval * challenge)
            .fold(Scalar::zero(), |acc, current_val| acc + current_val);

        Proof {
            commitment_to_witness: self.commitment_to_witness,
            evaluated_point: flattened_poly_evaluations,
            commitment_to_polynomial: Commitment::from_projective(flattened_poly_commitments),
        }
    }
    // Adds an evaluated point with the commitment to the polynomial which produced it
    pub fn add_part(&mut self, part: (Scalar, Commitment)) {
        self.evaluated_points.push(part.0);
        self.commitments_to_polynomials.push(part.1);
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Commitment(
    /// The commitment is a group element.
    pub G1Affine,
);

impl Commitment {
    pub fn from_projective(g: G1Projective) -> Self {
        Self(g.into())
    }
    pub fn from_affine(g: G1Affine) -> Self {
        Self(g)
    }

    pub fn empty() -> Self {
        Commitment(G1Affine::identity())
    }
}
