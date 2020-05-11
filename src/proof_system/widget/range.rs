use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearisation_poly::ProofEvaluations;

use dusk_bls12_381::{G1Affine, Scalar};
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Eq, PartialEq)]
pub struct RangeWidget {
    pub q_range: PreProcessedPolynomial,
}

#[cfg(feature = "serde")]
impl Serialize for RangeWidget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut logic_widget = serializer.serialize_struct("struct RangeWidget", 1)?;
        logic_widget.serialize_field("q_range", &self.q_range)?;
        logic_widget.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for RangeWidget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Qrange,
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
                        formatter.write_str("struct RangeWidget")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "q_range" => Ok(Field::Qrange),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct RangeWidgetVisitor;

        impl<'de> Visitor<'de> for RangeWidgetVisitor {
            type Value = RangeWidget;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct RangeWidget")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<RangeWidget, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let q_range = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(RangeWidget { q_range })
            }
        }

        const FIELDS: &[&str] = &["q_range"];
        deserializer.deserialize_struct("RangeWidget", FIELDS, RangeWidgetVisitor)
    }
}

impl RangeWidget {
    pub(crate) fn new(selector: (Polynomial, Commitment, Option<Evaluations>)) -> RangeWidget {
        RangeWidget {
            q_range: PreProcessedPolynomial::new(selector),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        range_separation_challenge: &Scalar,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        w_4_i_next: &Scalar,
    ) -> Scalar {
        let four = Scalar::from(4);
        let q_range_i = &self.q_range.evaluations.as_ref().unwrap()[index];

        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        // Delta([c(X) - 4 * d(X)]) + Delta([b(X) - 4 * c(X)]) + Delta([a(X) - 4 * b(X)]) + Delta([d(Xg) - 4 * a(X)]) * Q_Range(X)
        //
        let b_1 = delta(w_o_i - four * w_4_i);
        let b_2 = delta(w_r_i - four * w_o_i) * kappa;
        let b_3 = delta(w_l_i - four * w_r_i) * kappa_sq;
        let b_4 = delta(w_4_i_next - four * w_l_i) * kappa_cu;
        (b_1 + b_2 + b_3 + b_4) * q_range_i * range_separation_challenge
    }

    pub(crate) fn compute_linearisation(
        &self,
        range_separation_challenge: &Scalar,
        a_eval: &Scalar,
        b_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
    ) -> Polynomial {
        let four = Scalar::from(4);
        let q_range_poly = &self.q_range.polynomial;

        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        // Delta([c_eval - 4 * d_eval]) + Delta([b_eval - 4 * c_eval]) + Delta([a_eval - 4 * b_eval]) + Delta([d_next_eval - 4 * a_eval]) * Q_Range(X)
        let b_1 = delta(c_eval - four * d_eval);
        let b_2 = delta(b_eval - four * c_eval) * kappa;
        let b_3 = delta(a_eval - four * b_eval) * kappa_sq;
        let b_4 = delta(d_next_eval - four * a_eval) * kappa_cu;

        let t = (b_1 + b_2 + b_3 + b_4) * range_separation_challenge;

        q_range_poly * &t
    }

    pub(crate) fn compute_linearisation_commitment(
        &self,
        range_separation_challenge: &Scalar,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let four = Scalar::from(4);

        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let b_1 = delta(evaluations.c_eval - (four * evaluations.d_eval));
        let b_2 = delta(evaluations.b_eval - four * evaluations.c_eval) * kappa;
        let b_3 = delta(evaluations.a_eval - four * evaluations.b_eval) * kappa_sq;
        let b_4 = delta(evaluations.d_next_eval - (four * evaluations.a_eval)) * kappa_cu;

        scalars.push((b_1 + b_2 + b_3 + b_4) * range_separation_challenge);
        points.push(self.q_range.commitment.0);
    }
}

// Computes f(f-1)(f-2)(f-3)
fn delta(f: Scalar) -> Scalar {
    let f_1 = f - Scalar::one();
    let f_2 = f - Scalar::from(2);
    let f_3 = f - Scalar::from(3);
    f * f_1 * f_2 * f_3
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fft::EvaluationDomain;

    #[cfg(feature = "serde")]
    #[test]
    fn range_widget_serde_roundtrip() {
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

        // Build directly the widget since the `new()` impl doesn't check any
        // correctness on the inputs.
        let prep_poly_w_evals = PreProcessedPolynomial {
            polynomial: poly.clone(),
            commitment: comm,
            evaluations: Some(evals),
        };

        // Build directly the widget since the `new()` impl doesn't check any
        // correctness on the inputs.
        let range_widget = RangeWidget {
            q_range: prep_poly_w_evals,
        };

        // Roundtrip with evals
        let ser = bincode::serialize(&range_widget).unwrap();
        let deser: RangeWidget = bincode::deserialize(&ser).unwrap();
        assert_eq!(range_widget, deser);
    }
}
