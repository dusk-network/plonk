#![allow(clippy::too_many_arguments)]
use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::{G1Affine, Scalar};
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Eq, PartialEq)]
pub struct LogicWidget {
    pub q_c: PreProcessedPolynomial,
    pub q_logic: PreProcessedPolynomial,
}

#[cfg(feature = "serde")]
impl Serialize for LogicWidget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut logic_widget = serializer.serialize_struct("struct LogicWidget", 2)?;
        logic_widget.serialize_field("q_c", &self.q_c)?;
        logic_widget.serialize_field("q_logic", &self.q_logic)?;
        logic_widget.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for LogicWidget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Qc,
            Qlogic,
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
                        formatter.write_str("struct LogicWidget")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "q_c" => Ok(Field::Qc),
                            "q_logic" => Ok(Field::Qlogic),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct LogicWidgetVisitor;

        impl<'de> Visitor<'de> for LogicWidgetVisitor {
            type Value = LogicWidget;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct LogicWidget")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<LogicWidget, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let q_c = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_logic = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(LogicWidget { q_c, q_logic })
            }
        }

        const FIELDS: &[&str] = &["q_c", "q_logic"];
        deserializer.deserialize_struct("LogicWidget", FIELDS, LogicWidgetVisitor)
    }
}

impl LogicWidget {
    pub fn new(
        q_c: (Polynomial, Commitment, Option<Evaluations>),
        q_logic: (Polynomial, Commitment, Option<Evaluations>),
    ) -> LogicWidget {
        LogicWidget {
            q_logic: PreProcessedPolynomial::new(q_logic),
            q_c: PreProcessedPolynomial::new(q_c),
        }
    }

    pub fn compute_quotient_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_l_i_next: &Scalar,
        w_r_i: &Scalar,
        w_r_i_next: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        w_4_i_next: &Scalar,
    ) -> Scalar {
        let four = Scalar::from(4);

        let q_logic_i = &self.q_logic.evaluations.as_ref().unwrap()[index];
        let q_c_i = &self.q_c.evaluations.as_ref().unwrap()[index];

        let a = w_l_i_next - four * w_l_i;
        let c_0 = delta(a);

        let b = w_r_i_next - four * w_r_i;
        let c_1 = delta(b);

        let d = w_4_i_next - four * w_4_i;
        let c_2 = delta(d);

        let w = w_o_i;

        let c_3 = w - a * b;

        let c_4 = delta_xor_and(&a, &b, w, &d, &q_c_i);

        q_logic_i * (c_3 + c_0 + c_1 + c_2 + c_4)
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        a_next_eval: &Scalar,
        b_eval: &Scalar,
        b_next_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
        q_c_eval: &Scalar,
    ) -> Polynomial {
        let four = Scalar::from(4);

        let q_logic_poly = &self.q_logic.polynomial;

        let a = a_next_eval - four * a_eval;
        let c_0 = delta(a);

        let b = b_next_eval - four * b_eval;
        let c_1 = delta(b);

        let d = d_next_eval - four * d_eval;
        let c_2 = delta(d);

        let w = c_eval;

        let c_3 = w - a * b;

        let c_4 = delta_xor_and(&a, &b, w, &d, &q_c_eval);

        q_logic_poly * &(c_0 + c_1 + c_2 + c_3 + c_4)
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let four = Scalar::from(4);

        let a = evaluations.a_next_eval - four * evaluations.a_eval;
        let c_0 = delta(a);

        let b = evaluations.b_next_eval - four * evaluations.b_eval;
        let c_1 = delta(b);

        let d = evaluations.d_next_eval - four * evaluations.d_eval;
        let c_2 = delta(d);

        let w = evaluations.c_eval;

        let c_3 = w - a * b;

        let c_4 = delta_xor_and(&a, &b, &w, &d, &evaluations.q_c_eval);
        scalars.push(c_0 + c_1 + c_2 + c_3 + c_4);
        points.push(self.q_logic.commitment.0);
    }
}

// Computes f(f-1)(f-2)(f-3)
fn delta(f: Scalar) -> Scalar {
    let f_1 = f - Scalar::one();
    let f_2 = f - Scalar::from(2);
    let f_3 = f - Scalar::from(3);
    f * f_1 * f_2 * f_3
}

#[allow(non_snake_case)]
// The identity we want to check is q_logic * A = 0
// A = B + E
// B = q_c * [9c - 3(a+b)]
// E = 3(a+b+c) - 2F
// F = w[w(4w - 18(a+b) + 81) + 18(a^2 + b^2) - 81(a+b) + 83]
fn delta_xor_and(a: &Scalar, b: &Scalar, w: &Scalar, c: &Scalar, q_c: &Scalar) -> Scalar {
    let nine = Scalar::from(9u64);
    let two = Scalar::from(2u64);
    let three = Scalar::from(3u64);
    let four = Scalar::from(4u64);
    let eighteen = Scalar::from(18u64);
    let eighty_one = Scalar::from(81u64);
    let eighty_three = Scalar::from(83u64);

    let F = w
        * (w * (four * w - eighteen * (a + b) + eighty_one) + eighteen * (a.square() + b.square())
            - eighty_one * (a + b)
            + eighty_three);
    let E = three * (a + b + c) - (two * F);
    let B = q_c * ((nine * c) - three * (a + b));
    B + E
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fft::EvaluationDomain;

    #[cfg(feature = "serde")]
    #[test]
    fn q_logic_serde_roundtrip() {
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

        let logic_widget = LogicWidget {
            q_c: prep_poly_w_evals.clone(),
            q_logic: prep_poly_without_evals.clone(),
        };

        // Roundtrip with evals
        let ser = bincode::serialize(&logic_widget).unwrap();
        let deser: LogicWidget = bincode::deserialize(&ser).unwrap();
        assert_eq!(logic_widget, deser);
    }
}
