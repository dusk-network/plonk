use crate::fft::Evaluations;
use crate::proof_system::widget::{ArithmeticWidget, LogicWidget, PermutationWidget, RangeWidget};
use crate::transcript::TranscriptProtocol;
use merlin::Transcript;
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};
/// `PreProcessedCircuit` is a data structure that holds the commitments to
/// the selector and sigma polynomials.
///
/// By doing this, we can see the `PreProcessedCircuit` as a "circuit-shape descriptor"
/// since it only stores the commitments that describe the operations that we will perform
/// innside the circuit.
#[derive(Debug, Eq, PartialEq)]
pub struct PreProcessedCircuit {
    /// The number of gates in the circuit
    pub n: usize,
    /// Holds the polynomials, commitments and evaluations
    /// of all of the arithmetic-related gates.
    pub arithmetic: ArithmeticWidget,
    /// Holds the polynomials, commitments and evaluations
    /// of all of the range_constraint gates.
    pub range: RangeWidget,
    /// Holds the polynomials, commitments and evaluations
    /// of all of the logic_constraint gates.
    pub logic: LogicWidget,
    /// Holds the polynomials, commitments and evaluations
    /// related to the sigmas and also stores the linear
    /// evaluations.
    pub permutation: PermutationWidget,

    // Pre-processes the 4n Evaluations for the vanishing polynomial, so they do not
    // need to be computed at the proving stage.
    // Note: With this, we can combine all parts of the quotient polynomial in their evaluation phase and
    // divide by the quotient polynomial without having to perform IFFT
    pub(crate) v_h_coset_4n: Evaluations,
}

impl PreProcessedCircuit {
    pub(crate) fn seed_transcript(&self, transcript: &mut Transcript) {
        transcript.append_commitment(b"q_m", &self.arithmetic.q_m.commitment);
        transcript.append_commitment(b"q_l", &self.arithmetic.q_l.commitment);
        transcript.append_commitment(b"q_r", &self.arithmetic.q_r.commitment);
        transcript.append_commitment(b"q_o", &self.arithmetic.q_o.commitment);
        transcript.append_commitment(b"q_c", &self.arithmetic.q_c.commitment);
        transcript.append_commitment(b"q_4", &self.arithmetic.q_4.commitment);
        transcript.append_commitment(b"q_arith", &self.arithmetic.q_arith.commitment);
        transcript.append_commitment(b"q_range", &self.range.q_range.commitment);
        transcript.append_commitment(b"q_logic", &self.logic.q_logic.commitment);

        transcript.append_commitment(b"left_sigma", &self.permutation.left_sigma.commitment);
        transcript.append_commitment(b"right_sigma", &self.permutation.right_sigma.commitment);
        transcript.append_commitment(b"out_sigma", &self.permutation.out_sigma.commitment);
        transcript.append_commitment(b"fourth_sigma", &self.permutation.fourth_sigma.commitment);

        // Append circuit size to transcript
        transcript.circuit_domain_sep(self.n as u64);
    }
}

#[cfg(feature = "serde")]
impl Serialize for PreProcessedCircuit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut prep_circ = serializer.serialize_struct("struct PreProcessedCircuit", 6)?;
        prep_circ.serialize_field("n", &self.n)?;
        prep_circ.serialize_field("arith_widg", &self.arithmetic)?;
        prep_circ.serialize_field("logic_widg", &self.logic)?;
        prep_circ.serialize_field("range_widg", &self.range)?;
        prep_circ.serialize_field("perm_widg", &self.permutation)?;
        prep_circ.serialize_field("v_h_coset_4n", &self.v_h_coset_4n)?;
        prep_circ.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PreProcessedCircuit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            N,
            ArithWidget,
            LogicWidget,
            RangeWidget,
            PermWidget,
            VhCoset4n,
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
                        formatter.write_str("struct PreProcessedCircuit")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "n" => Ok(Field::N),
                            "arith_widg" => Ok(Field::ArithWidget),
                            "logic_widg" => Ok(Field::LogicWidget),
                            "range_widg" => Ok(Field::RangeWidget),
                            "perm_widg" => Ok(Field::PermWidget),
                            "v_h_coset_4n" => Ok(Field::VhCoset4n),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PreProcessedCircuitVisitor;

        impl<'de> Visitor<'de> for PreProcessedCircuitVisitor {
            type Value = PreProcessedCircuit;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct PreProcessedCircuit")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<PreProcessedCircuit, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let n = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let arith_widg = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let logic_widg = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let range_widg = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let perm_widg = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let v_h_coset_4n = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(PreProcessedCircuit {
                    n,
                    arithmetic: arith_widg,
                    logic: logic_widg,
                    range: range_widg,
                    permutation: perm_widg,
                    v_h_coset_4n,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "n",
            "arith_widg",
            "logic_widg",
            "range_widg",
            "perm_widg",
            "v_h_coset_4n",
            "q_arith",
        ];
        deserializer.deserialize_struct("PreProcessedCircuit", FIELDS, PreProcessedCircuitVisitor)
    }
}

impl PreProcessedCircuit {
    pub(crate) fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fft::{EvaluationDomain, Polynomial};
    use crate::proof_system::widget::PreProcessedPolynomial;
    use dusk_bls12_381::{G1Affine, Scalar};

    #[cfg(feature = "serde")]
    #[test]
    fn prep_circuit_serde_roundtrip() {
        use bincode;
        let n = 24562352usize;
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
            evaluations: Some(evals.clone()),
        };

        // Build directly the widget since the `new()` impl doesn't check any
        // correctness on the inputs.
        let prep_poly_without_evals = PreProcessedPolynomial {
            polynomial: poly,
            commitment: comm,
            evaluations: None,
        };

        // Build directly the widget since the `new()` impl doesn't check any
        // correctness on the inputs.
        let arith_widget = ArithmeticWidget {
            q_m: prep_poly_w_evals.clone(),
            q_l: prep_poly_without_evals.clone(),
            q_r: prep_poly_without_evals.clone(),
            q_o: prep_poly_w_evals.clone(),
            q_c: prep_poly_w_evals.clone(),
            q_4: prep_poly_w_evals.clone(),
            q_arith: prep_poly_without_evals.clone(),
        };

        // Build directly the widget since the `new()` impl doesn't check any
        // correctness on the inputs.
        let logic_widget = LogicWidget {
            q_c: prep_poly_w_evals.clone(),
            q_logic: prep_poly_without_evals.clone(),
        };

        // Build directly the widget since the `new()` impl doesn't check any
        // correctness on the inputs.
        let perm_widget = PermutationWidget {
            left_sigma: prep_poly_w_evals.clone(),
            right_sigma: prep_poly_without_evals.clone(),
            out_sigma: prep_poly_without_evals.clone(),
            fourth_sigma: prep_poly_w_evals.clone(),
            linear_evaluations: evals.clone(),
        };

        // Build directly the widget since the `new()` impl doesn't check any
        // correctness on the inputs.
        let range_widget = RangeWidget {
            q_range: prep_poly_w_evals,
        };

        // Build directly the widget since the `new()` impl doesn't check any
        // correctness on the inputs.
        let v_h_coset_4n = evals;

        let prep_circ = PreProcessedCircuit {
            n,
            arithmetic: arith_widget,
            logic: logic_widget,
            range: range_widget,
            permutation: perm_widget,
            v_h_coset_4n,
        };

        // Roundtrip with evals
        let ser = bincode::serialize(&prep_circ).unwrap();
        let deser: PreProcessedCircuit = bincode::deserialize(&ser).unwrap();
        assert_eq!(prep_circ, deser);
    }
}
