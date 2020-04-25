use crate::commitment_scheme::kzg10::Commitment;
use crate::fft::{Evaluations, Polynomial};

pub mod arithmetic;
pub mod logic;
pub mod permutation;
pub mod range;

pub use arithmetic::ArithmeticWidget;
pub use logic::LogicWidget;
pub use permutation::PermutationWidget;
pub use range::RangeWidget;
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PreProcessedPolynomial {
    pub(crate) polynomial: Polynomial,
    pub(crate) commitment: Commitment,
    pub(crate) evaluations: Option<Evaluations>,
}

#[cfg(feature = "serde")]
impl Serialize for PreProcessedPolynomial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut eval_dom = serializer.serialize_struct("struct PreProcessedPolynomial", 3)?;
        eval_dom.serialize_field("poly", &self.polynomial)?;
        eval_dom.serialize_field("comm", &self.commitment)?;
        eval_dom.serialize_field("evals", &self.evaluations)?;
        eval_dom.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PreProcessedPolynomial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Poly,
            Comm,
            Evals,
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
                        formatter.write_str("struct PreProcessedPolynomial")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "poly" => Ok(Field::Poly),
                            "comm" => Ok(Field::Comm),
                            "evals" => Ok(Field::Evals),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PreProcessedPolynomialVisitor;

        impl<'de> Visitor<'de> for PreProcessedPolynomialVisitor {
            type Value = PreProcessedPolynomial;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct PreProcessedPolynomial")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PreProcessedPolynomial, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let polynomial = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let commitment = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let evaluations = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(PreProcessedPolynomial {
                    polynomial,
                    commitment,
                    evaluations,
                })
            }
        }

        const FIELDS: &[&str] = &["poly", "comm", "evals"];
        deserializer.deserialize_struct(
            "PreProcessedPolynomial",
            FIELDS,
            PreProcessedPolynomialVisitor,
        )
    }
}

impl PreProcessedPolynomial {
    pub fn new(t: (Polynomial, Commitment, Option<Evaluations>)) -> PreProcessedPolynomial {
        PreProcessedPolynomial {
            polynomial: t.0,
            commitment: t.1,
            evaluations: t.2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fft::EvaluationDomain;
    use dusk-bls12_381::{G1Affine, Scalar};

    #[cfg(feature = "serde")]
    #[test]
    fn prep_poly_serde_roundtrip() {
        use bincode;
        let coeffs = vec![
            Scalar::one(),
            Scalar::one(),
            Scalar::one(),
            Scalar::one(),
            Scalar::one(),
            Scalar::one(),
            Scalar::one(),
            Scalar::one(),
        ];
        let dom = EvaluationDomain::new(coeffs.len()).unwrap();
        let evals = Evaluations::from_vec_and_domain(coeffs.clone(), dom);
        let poly = Polynomial::from_coefficients_vec(coeffs);
        let comm = crate::commitment_scheme::kzg10::Commitment::from_affine(G1Affine::generator());

        let prep_poly_w_evals = PreProcessedPolynomial {
            polynomial: poly.clone(),
            commitment: comm,
            evaluations: Some(evals),
        };
        let prep_poly_without_evals = PreProcessedPolynomial {
            polynomial: poly,
            commitment: comm,
            evaluations: None,
        };

        // Roundtrip with evals
        let ser = bincode::serialize(&prep_poly_w_evals).unwrap();
        let deser: PreProcessedPolynomial = bincode::deserialize(&ser).unwrap();
        assert_eq!(prep_poly_w_evals, deser);

        // Roundtrip without evals
        let ser = bincode::serialize(&prep_poly_without_evals).unwrap();
        let deser: PreProcessedPolynomial = bincode::deserialize(&ser).unwrap();
        assert_eq!(prep_poly_without_evals, deser);
    }
}
