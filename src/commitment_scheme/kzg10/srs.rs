//! The Public Parameters can also be referred to as the Structured Reference String (SRS).
use super::{
    errors::{KZG10Errors, PolyCommitSchemeError},
    key::{CommitKey, OpeningKey},
};
use crate::util;
use dusk_bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared};
use failure::Error;
use rand_core::RngCore;

/// The Public Parameters can also be referred to as the Structured Reference String (SRS).
/// It is available to both the prover and verifier and allows the verifier to
/// efficiently verify and make claims about polynomials up to and including a configured degree.
#[derive(Debug)]
pub struct PublicParameters {
    /// Key used to generate proofs for composed circuits.
    pub commit_key: CommitKey,
    /// Key used to verify proofs for composed circuits.
    pub opening_key: OpeningKey,
}

#[cfg(feature = "serde")]
use serde::{
    self, de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};

#[cfg(feature = "serde")]
impl Serialize for PublicParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut params = serializer.serialize_struct("struct PublicParameters", 2)?;
        params.serialize_field("ck", &self.commit_key)?;
        params.serialize_field("vk", &self.opening_key)?;
        params.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PublicParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Ck,
            Vk,
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
                        formatter.write_str("struct PublicParameters")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "ck" => Ok(Field::Ck),
                            "vk" => Ok(Field::Vk),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PublicParametersVisitor;

        impl<'de> Visitor<'de> for PublicParametersVisitor {
            type Value = PublicParameters;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct PublicParameters")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PublicParameters, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let commit_key = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let opening_key = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                Ok(PublicParameters {
                    commit_key,
                    opening_key,
                })
            }
        }

        const FIELDS: &[&str] = &["ck", "vk"];
        deserializer.deserialize_struct("PublicParameters", FIELDS, PublicParametersVisitor)
    }
}

impl PublicParameters {
    /// Setup generates the public parameters using a random number generator.
    /// This method will in most cases be used for testing and exploration.
    /// In reality, a `Trusted party` or a `Multiparty Computation` will used to generate the SRS.
    /// Returns an error if the configured degree is less than one.
    pub fn setup<R: RngCore>(
        max_degree: usize,
        mut rng: &mut R,
    ) -> Result<PublicParameters, Error> {
        // Cannot commit to constants
        if max_degree < 1 {
            return Err(PolyCommitSchemeError(KZG10Errors::DegreeIsZero.into()).into());
        }

        // Generate the secret scalar beta
        let beta = util::random_scalar(&mut rng);

        // Compute powers of beta up to and including beta^max_degree
        let powers_of_beta = util::powers_of(&beta, max_degree);

        // Powers of G1 that will be used to commit to a specified polynomial
        let g = util::random_g1_point(&mut rng);
        let powers_of_g: Vec<G1Projective> =
            util::slow_multiscalar_mul_single_base(&powers_of_beta, g);
        assert_eq!(powers_of_g.len(), max_degree + 1);

        // Normalise all projective points
        let mut normalised_g = vec![G1Affine::identity(); max_degree + 1];
        G1Projective::batch_normalize(&powers_of_g, &mut normalised_g);

        // Compute beta*G2 element and stored cached elements for verifying multiple proofs.
        let h: G2Affine = util::random_g2_point(&mut rng).into();
        let beta_h: G2Affine = (h * beta).into();
        let prepared_h: G2Prepared = G2Prepared::from(h);
        let prepared_beta_h = G2Prepared::from(beta_h);

        Ok(PublicParameters {
            commit_key: CommitKey {
                powers_of_g: normalised_g,
            },
            opening_key: OpeningKey {
                g: g.into(),
                h,
                beta_h,
                prepared_h,
                prepared_beta_h,
            },
        })
    }

    /// Trim truncates the prover key to allow the prover to commit to polynomials up to the
    /// and including the truncated degree.
    /// Returns an error if the truncated degree is larger than the public parameters configured degree.
    pub fn trim(&self, truncated_degree: usize) -> Result<(CommitKey, OpeningKey), Error> {
        let truncated_prover_key = self.commit_key.truncate(truncated_degree)?;
        let opening_key = self.opening_key.clone();
        Ok((truncated_prover_key, opening_key))
    }

    /// Max degree specifies the largest polynomial that this prover key can commit to.
    pub fn max_degree(&self) -> usize {
        self.commit_key.max_degree()
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use dusk_bls12_381::Scalar;
    #[test]
    fn test_powers_of() {
        let x = Scalar::from(10u64);
        let degree = 100u64;

        let powers_of_x = util::powers_of(&x, degree as usize);

        for (i, x_i) in powers_of_x.iter().enumerate() {
            assert_eq!(*x_i, x.pow(&[i as u64, 0, 0, 0]))
        }

        let last_element = powers_of_x.last().unwrap();
        assert_eq!(*last_element, x.pow(&[degree, 0, 0, 0]))
    }

    #[cfg(feature = "serde")]
    #[test]
    fn srs_serde_roundtrip() {
        use bincode;
        let srs = PublicParameters::setup(1 << 12, &mut rand::thread_rng()).unwrap();

        let ser = bincode::serialize(&srs).unwrap();
        let deser: PublicParameters = bincode::deserialize(&ser).unwrap();

        assert!(&srs.commit_key.powers_of_g[..] == &deser.commit_key.powers_of_g[..]);
        assert!(srs.opening_key.g == deser.opening_key.g);
        assert!(srs.opening_key.h == deser.opening_key.h);
        assert!(srs.opening_key.beta_h == deser.opening_key.beta_h);
    }
}
