//! A polynomial represented in evaluations form over a domain of size 2^n.

use super::domain::EvaluationDomain;
use super::polynomial::Polynomial;
use core::ops::{Add, AddAssign, DivAssign, Index, Mul, MulAssign, Sub, SubAssign};
use dusk_bls12_381::Scalar;
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};
/// Stores a polynomial in evaluation form.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Evaluations {
    /// The evaluations of a polynomial over the domain `D`
    pub evals: Vec<Scalar>,
    #[doc(hidden)]
    domain: EvaluationDomain,
}

#[cfg(feature = "serde")]
impl Serialize for Evaluations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut eval_dom = serializer.serialize_struct("struct Evaluations", 2)?;
        eval_dom.serialize_field("evals", &self.evals)?;
        eval_dom.serialize_field("domain", &self.domain)?;
        eval_dom.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Evaluations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Evals,
            EvalDomain,
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
                        formatter.write_str("struct Evaluations")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "evals" => Ok(Field::Evals),
                            "domain" => Ok(Field::EvalDomain),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct EvaluationsVisitor;

        impl<'de> Visitor<'de> for EvaluationsVisitor {
            type Value = Evaluations;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct Evaluations")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Evaluations, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let evals = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let domain = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(Evaluations { evals, domain })
            }
        }

        const FIELDS: &[&str] = &["evals", "domain"];
        deserializer.deserialize_struct("Evaluations", FIELDS, EvaluationsVisitor)
    }
}
impl Evaluations {
    /// Construct `Self` from evaluations and a domain.
    pub fn from_vec_and_domain(evals: Vec<Scalar>, domain: EvaluationDomain) -> Self {
        Self { evals, domain }
    }

    /// Interpolate a polynomial from a list of evaluations
    pub fn interpolate_by_ref(&self) -> Polynomial {
        Polynomial::from_coefficients_vec(self.domain.ifft(&self.evals))
    }

    /// Interpolate a polynomial from a list of evaluations
    pub fn interpolate(self) -> Polynomial {
        let Self { mut evals, domain } = self;
        domain.ifft_in_place(&mut evals);
        Polynomial::from_coefficients_vec(evals)
    }
}

impl Index<usize> for Evaluations {
    type Output = Scalar;

    fn index(&self, index: usize) -> &Scalar {
        &self.evals[index]
    }
}

impl<'a, 'b> Mul<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn mul(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result *= other;
        result
    }
}

impl<'a> MulAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn mul_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a *= b);
    }
}

impl<'a, 'b> Add<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn add(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result += other;
        result
    }
}

impl<'a> AddAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn add_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a += b);
    }
}

impl<'a, 'b> Sub<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn sub(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result -= other;
        result
    }
}

impl<'a> SubAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn sub_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a -= b);
    }
}

impl<'a> DivAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn div_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a *= b.invert().unwrap());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn evals_serde_roundtrip() {
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
        let evals = Evaluations::from_vec_and_domain(coeffs, dom);
        let ser = bincode::serialize(&evals).unwrap();
        let deser: Evaluations = bincode::deserialize(&ser).unwrap();

        assert_eq!(evals, deser);
    }
}
