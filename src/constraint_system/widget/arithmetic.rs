use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::{G1Affine, Scalar};
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Eq, PartialEq)]
pub struct ArithmeticWidget {
    pub q_m: PreProcessedPolynomial,
    pub q_l: PreProcessedPolynomial,
    pub q_r: PreProcessedPolynomial,
    pub q_o: PreProcessedPolynomial,
    pub q_c: PreProcessedPolynomial,
    pub q_4: PreProcessedPolynomial,
    pub q_arith: PreProcessedPolynomial,
}

#[cfg(feature = "serde")]
impl Serialize for ArithmeticWidget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut arith_widget = serializer.serialize_struct("struct ArithmeticWidget", 7)?;
        arith_widget.serialize_field("q_m", &self.q_m)?;
        arith_widget.serialize_field("q_l", &self.q_l)?;
        arith_widget.serialize_field("q_r", &self.q_r)?;
        arith_widget.serialize_field("q_o", &self.q_o)?;
        arith_widget.serialize_field("q_c", &self.q_c)?;
        arith_widget.serialize_field("q_4", &self.q_4)?;
        arith_widget.serialize_field("q_arith", &self.q_arith)?;
        arith_widget.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ArithmeticWidget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Qm,
            Ql,
            Qr,
            Qo,
            Qc,
            Q4,
            Qarith,
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
                        formatter.write_str("struct ArithmeticWidget")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "q_m" => Ok(Field::Qm),
                            "q_l" => Ok(Field::Ql),
                            "q_r" => Ok(Field::Qr),
                            "q_o" => Ok(Field::Qo),
                            "q_c" => Ok(Field::Qc),
                            "q_4" => Ok(Field::Q4),
                            "q_arith" => Ok(Field::Qarith),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ArithmeticWidgetVisitor;

        impl<'de> Visitor<'de> for ArithmeticWidgetVisitor {
            type Value = ArithmeticWidget;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct ArithmeticWidget")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ArithmeticWidget, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let q_m = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_l = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_r = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_o = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_c = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_4 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_arith = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ArithmeticWidget {
                    q_m,
                    q_l,
                    q_r,
                    q_o,
                    q_c,
                    q_4,
                    q_arith,
                })
            }
        }

        const FIELDS: &[&str] = &["q_m", "q_l", "q_r", "q_o", "q_c", "q_4", "q_arith"];
        deserializer.deserialize_struct("ArithmeticWidget", FIELDS, ArithmeticWidgetVisitor)
    }
}

impl ArithmeticWidget {
    #[allow(clippy::type_complexity)]
    pub fn new(
        selectors: (
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
            (Polynomial, Commitment, Option<Evaluations>),
        ),
    ) -> ArithmeticWidget {
        ArithmeticWidget {
            q_m: PreProcessedPolynomial::new(selectors.0),
            q_l: PreProcessedPolynomial::new(selectors.1),
            q_r: PreProcessedPolynomial::new(selectors.2),
            q_o: PreProcessedPolynomial::new(selectors.3),
            q_c: PreProcessedPolynomial::new(selectors.4),
            q_4: PreProcessedPolynomial::new(selectors.5),
            q_arith: PreProcessedPolynomial::new(selectors.6),
        }
    }
    pub fn compute_quotient_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_r_i: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
    ) -> Scalar {
        let q_m_i = self.q_m.evaluations.as_ref().unwrap()[index];
        let q_l_i = self.q_l.evaluations.as_ref().unwrap()[index];
        let q_r_i = self.q_r.evaluations.as_ref().unwrap()[index];
        let q_o_i = self.q_o.evaluations.as_ref().unwrap()[index];
        let q_c_i = self.q_c.evaluations.as_ref().unwrap()[index];
        let q_4_i = self.q_4.evaluations.as_ref().unwrap()[index];
        let q_arith_i = self.q_arith.evaluations.as_ref().unwrap()[index];

        // (a(x)b(x)q_M(x) + a(x)q_L(x) + b(X)q_R(x) + c(X)q_O(X) + d(x)q_4(X) + Q_C(X)) * Q_Arith(X)
        //
        let a_1 = w_l_i * w_r_i * q_m_i;
        let a_2 = w_l_i * q_l_i;
        let a_3 = w_r_i * q_r_i;
        let a_4 = w_o_i * q_o_i;
        let a_5 = w_4_i * q_4_i;
        let a_6 = q_c_i;
        (a_1 + a_2 + a_3 + a_4 + a_5 + a_6) * q_arith_i
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        b_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        q_arith_eval: &Scalar,
    ) -> Polynomial {
        let q_m_poly = &self.q_m.polynomial;
        let q_l_poly = &self.q_l.polynomial;
        let q_r_poly = &self.q_r.polynomial;
        let q_o_poly = &self.q_o.polynomial;
        let q_c_poly = &self.q_c.polynomial;
        let q_4_poly = &self.q_4.polynomial;

        // (a_eval * b_eval * q_m_poly + a_eval * q_l + b_eval * q_r + c_eval * q_o + d_eval * q_4 + q_c) * q_arith_eval * alpha
        //
        // a_eval * b_eval * q_m_poly
        let ab = a_eval * b_eval;
        let a_0 = q_m_poly * &ab;

        // a_eval * q_l
        let a_1 = q_l_poly * a_eval;

        // b_eval * q_r
        let a_2 = q_r_poly * b_eval;

        //c_eval * q_o
        let a_3 = q_o_poly * c_eval;

        // d_eval * q_4
        let a_4 = q_4_poly * d_eval;

        let mut a = &a_0 + &a_1;
        a = &a + &a_2;
        a = &a + &a_3;
        a = &a + &a_4;
        a = &a + q_c_poly;
        a = &a * q_arith_eval;

        a
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let q_arith_eval = evaluations.q_arith_eval;
        scalars.push(evaluations.a_eval * evaluations.b_eval * q_arith_eval);
        points.push(self.q_m.commitment.0);

        scalars.push(evaluations.a_eval * q_arith_eval);
        points.push(self.q_l.commitment.0);

        scalars.push(evaluations.b_eval * q_arith_eval);
        points.push(self.q_r.commitment.0);

        scalars.push(evaluations.c_eval * q_arith_eval);
        points.push(self.q_o.commitment.0);

        scalars.push(evaluations.d_eval * q_arith_eval);
        points.push(self.q_4.commitment.0);

        scalars.push(q_arith_eval);
        points.push(self.q_c.commitment.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fft::EvaluationDomain;

    #[cfg(feature = "serde")]
    #[test]
    fn q_arith_serde_roundtrip() {
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

        let arith_widget = ArithmeticWidget {
            q_m: prep_poly_w_evals.clone(),
            q_l: prep_poly_without_evals.clone(),
            q_r: prep_poly_without_evals.clone(),
            q_o: prep_poly_w_evals.clone(),
            q_c: prep_poly_w_evals.clone(),
            q_4: prep_poly_w_evals,
            q_arith: prep_poly_without_evals,
        };

        // Roundtrip with evals
        let ser = bincode::serialize(&arith_widget).unwrap();
        let deser: ArithmeticWidget = bincode::deserialize(&ser).unwrap();
        assert_eq!(arith_widget, deser);
    }
}
