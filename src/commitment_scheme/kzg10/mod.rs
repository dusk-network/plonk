//! Implementation of the KZG10 polynomial commitment scheme.
use bls12_381::{G1Affine, G1Projective, Scalar};
pub mod errors;
pub mod key;
pub mod srs;
use crate::transcript::TranscriptProtocol;
use crate::util::powers_of;
pub use key::{ProverKey, VerifierKey};
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};
pub use srs::PublicParameters;

#[derive(Copy, Clone, Debug)]
/// Proof that a polynomial `p` was correctly evaluated at a point `z`
/// producing the evaluated point p(z).
pub struct Proof {
    /// This is a commitment to the witness polynomial.
    pub commitment_to_witness: Commitment,
    /// This is the result of evaluating a polynomial at the point `z`.
    pub evaluated_point: Scalar,
    /// This is the commitment to the polynomial that you want to prove a statement about.
    pub commitment_to_polynomial: Commitment,
}

/// Proof that multiple polynomials were correctly evaluated at a point `z`,
/// each producing their respective evaluated points p_i(z).
#[derive(Debug)]
pub struct AggregateProof {
    /// This is a commitment to the aggregated witness polynomial.
    pub commitment_to_witness: Commitment,
    /// These are the results of the evaluating each polynomial at the point `z`.
    pub evaluated_points: Vec<Scalar>,
    /// These are the commitments to the polynomials which you want to prove a statement about.
    pub commitments_to_polynomials: Vec<Commitment>,
}

impl AggregateProof {
    /// Initialises an `AggregatedProof` with the commitment to the witness.
    pub fn with_witness(witness: Commitment) -> AggregateProof {
        AggregateProof {
            commitment_to_witness: witness,
            evaluated_points: Vec::new(),
            commitments_to_polynomials: Vec::new(),
        }
    }

    /// Adds an evaluated point with the commitment to the polynomial which produced it.
    pub fn add_part(&mut self, part: (Scalar, Commitment)) {
        self.evaluated_points.push(part.0);
        self.commitments_to_polynomials.push(part.1);
    }

    /// Flattens an `AggregateProof` into a `Proof`.
    /// The transcript must have the same view as the transcript that was used to aggregate the witness in the proving stage.
    pub fn flatten(&self, transcript: &mut dyn TranscriptProtocol) -> Proof {
        let challenge = transcript.challenge_scalar(b"aggregate_witness");
        let powers = powers_of(&challenge, self.commitments_to_polynomials.len() - 1);

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
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// Holds a commitment to a polynomial in a form of a `G1Affine` Bls12_381 point.
pub struct Commitment(
    /// The commitment is a group element.
    pub G1Affine,
);

#[cfg(feature = "serde")]
impl Serialize for Commitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("struct Commitment", 1)?;
        state.serialize_field("g1affine", &self.0)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Commitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            G1Affine,
        };

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        formatter.write_str("commitment")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "g1affine" => Ok(Field::G1Affine),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct CommitmentVisitor;

        impl<'de> Visitor<'de> for CommitmentVisitor {
            type Value = Commitment;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct Commitment")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Commitment, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let g1_affine = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(Commitment(g1_affine))
            }
        }

        const FIELDS: &[&str] = &["g1affine"];
        deserializer.deserialize_struct("Commitment", FIELDS, CommitmentVisitor)
    }
}

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

mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[cfg(feature = "serde")]
    #[test]
    fn commitment_serde_roundtrip() {
        use bincode;
        let comm_og = Commitment(G1Affine::generator());
        let ser = bincode::serialize(&comm_og).unwrap();
        let deser: Commitment = bincode::deserialize(&ser).unwrap();

        assert_eq!(comm_og.0, deser.0);
    }
}
