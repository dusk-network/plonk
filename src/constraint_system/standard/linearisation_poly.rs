use crate::constraint_system::standard::PreProcessedCircuit;
use crate::fft::{EvaluationDomain, Polynomial};
use bls12_381::Scalar;
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

/// Evaluations at points `z` or and `z * root of unity`
pub struct Evaluations {
    pub proof: ProofEvaluations,
    // Evaluation of the linearisation sigma polynomial at `z`
    pub quot_eval: Scalar,
}

/// Proof Evaluations is a subset of all of the evaluations. These evaluations will be added to the proof
#[derive(Debug, Eq, PartialEq)]
pub struct ProofEvaluations {
    // Evaluation of the witness polynomial for the left wire at `z`
    pub a_eval: Scalar,
    // Evaluation of the witness polynomial for the right wire at `z`
    pub b_eval: Scalar,
    // Evaluation of the witness polynomial for the output wire at `z`
    pub c_eval: Scalar,
    // Evaluation of the witness polynomial for the fourth wire at `z`
    pub d_eval: Scalar,
    //
    pub a_next_eval: Scalar,
    //
    pub b_next_eval: Scalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of unity`
    pub d_next_eval: Scalar,
    // Evaluation of the arithmetic selector polynomial at `z`
    pub q_arith_eval: Scalar,
    //
    pub q_c_eval: Scalar,
    // Evaluation of the left sigma polynomial at `z`
    pub left_sigma_eval: Scalar,
    // Evaluation of the right sigma polynomial at `z`
    pub right_sigma_eval: Scalar,
    // Evaluation of the out sigma polynomial at `z`
    pub out_sigma_eval: Scalar,

    // Evaluation of the linearisation sigma polynomial at `z`
    pub lin_poly_eval: Scalar,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of unity`
    pub perm_eval: Scalar,
}

#[cfg(feature = "serde")]
impl Serialize for ProofEvaluations {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut proof_evals = serializer.serialize_struct("struct ProofEvaluations", 14)?;
        proof_evals.serialize_field("a_eval", &self.a_eval)?;
        proof_evals.serialize_field("b_eval", &self.b_eval)?;
        proof_evals.serialize_field("c_eval", &self.c_eval)?;
        proof_evals.serialize_field("d_eval", &self.d_eval)?;
        proof_evals.serialize_field("a_next_eval", &self.a_next_eval)?;
        proof_evals.serialize_field("b_next_eval", &self.b_next_eval)?;
        proof_evals.serialize_field("d_next_eval", &self.d_next_eval)?;
        proof_evals.serialize_field("q_arith_eval", &self.q_arith_eval)?;
        proof_evals.serialize_field("q_c_eval", &self.q_c_eval)?;
        proof_evals.serialize_field("left_sig_eval", &self.left_sigma_eval)?;
        proof_evals.serialize_field("right_sig_eval", &self.right_sigma_eval)?;
        proof_evals.serialize_field("out_sig_eval", &self.out_sigma_eval)?;
        proof_evals.serialize_field("lin_poly_eval", &self.lin_poly_eval)?;
        proof_evals.serialize_field("perm_eval", &self.perm_eval)?;
        proof_evals.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ProofEvaluations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Aeval,
            Beval,
            Ceval,
            Deval,
            ANextEval,
            BNextEval,
            DNextEval,
            QArithEval,
            QCEval,
            LeftSigEval,
            RightSigEval,
            OutSigEval,
            LinPolyEval,
            PermEval,
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
                        formatter.write_str("struct ProofEvaluations")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "a_eval" => Ok(Field::Aeval),
                            "b_eval" => Ok(Field::Beval),
                            "c_eval" => Ok(Field::Ceval),
                            "d_eval" => Ok(Field::Deval),
                            "a_next_eval" => Ok(Field::ANextEval),
                            "b_next_eval" => Ok(Field::BNextEval),
                            "d_next_eval" => Ok(Field::DNextEval),
                            "q_arith_eval" => Ok(Field::QArithEval),
                            "q_c_eval" => Ok(Field::QCEval),
                            "left_sig_eval" => Ok(Field::LeftSigEval),
                            "right_sig_eval" => Ok(Field::RightSigEval),
                            "out_sig_eval" => Ok(Field::OutSigEval),
                            "lin_poly_eval" => Ok(Field::LinPolyEval),
                            "perm_eval" => Ok(Field::PermEval),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ProofEvaluationsVisitor;

        impl<'de> Visitor<'de> for ProofEvaluationsVisitor {
            type Value = ProofEvaluations;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct ProofEvaluations")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<ProofEvaluations, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let a_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let b_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let c_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let d_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let a_next_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let b_next_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let d_next_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_arith_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_c_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let left_sigma_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let right_sigma_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let out_sigma_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let lin_poly_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let perm_eval = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(ProofEvaluations {
                    a_eval,
                    b_eval,
                    c_eval,
                    d_eval,
                    a_next_eval,
                    b_next_eval,
                    d_next_eval,
                    q_arith_eval,
                    q_c_eval,
                    left_sigma_eval,
                    right_sigma_eval,
                    out_sigma_eval,
                    lin_poly_eval,
                    perm_eval,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "a_eval",
            "b_eval",
            "c_eval",
            "d_eval",
            "a_next_eval",
            "b_next_eval",
            "d_next_eval",
            "q_arith_eval",
            "q_c_eval",
            "left_sig_eval",
            "right_sig_eval",
            "out_sig_eval",
            "lin_poly_eval",
            "perm_eval",
        ];
        deserializer.deserialize_struct("ProofEvaluations", FIELDS, ProofEvaluationsVisitor)
    }
}

#[allow(clippy::too_many_arguments)]
/// Compute the linearisation polynomial
pub fn compute(
    domain: &EvaluationDomain,
    preprocessed_circuit: &PreProcessedCircuit,
    (alpha, beta, gamma, z_challenge): &(Scalar, Scalar, Scalar, Scalar),
    w_l_poly: &Polynomial,
    w_r_poly: &Polynomial,
    w_o_poly: &Polynomial,
    w_4_poly: &Polynomial,
    t_x_poly: &Polynomial,
    z_poly: &Polynomial,
) -> (Polynomial, Evaluations) {
    // Compute evaluations
    let quot_eval = t_x_poly.evaluate(z_challenge);
    let a_eval = w_l_poly.evaluate(z_challenge);
    let b_eval = w_r_poly.evaluate(z_challenge);
    let c_eval = w_o_poly.evaluate(z_challenge);
    let d_eval = w_4_poly.evaluate(z_challenge);
    let left_sigma_eval = preprocessed_circuit
        .permutation
        .left_sigma
        .polynomial
        .evaluate(z_challenge);
    let right_sigma_eval = preprocessed_circuit
        .permutation
        .right_sigma
        .polynomial
        .evaluate(z_challenge);
    let out_sigma_eval = preprocessed_circuit
        .permutation
        .out_sigma
        .polynomial
        .evaluate(z_challenge);
    let q_arith_eval = preprocessed_circuit
        .arithmetic
        .q_arith
        .polynomial
        .evaluate(z_challenge);
    let q_c_eval = preprocessed_circuit
        .logic
        .q_c
        .polynomial
        .evaluate(z_challenge);

    let a_next_eval = w_l_poly.evaluate(&(z_challenge * domain.group_gen));
    let b_next_eval = w_r_poly.evaluate(&(z_challenge * domain.group_gen));
    let d_next_eval = w_4_poly.evaluate(&(z_challenge * domain.group_gen));
    let perm_eval = z_poly.evaluate(&(z_challenge * domain.group_gen));

    let f_1 = compute_circuit_satisfiability(
        &a_eval,
        &b_eval,
        &c_eval,
        &d_eval,
        &a_next_eval,
        &b_next_eval,
        &d_next_eval,
        &q_arith_eval,
        &q_c_eval,
        preprocessed_circuit,
    );

    let f_2 = preprocessed_circuit.permutation.compute_linearisation(
        z_challenge,
        (alpha, beta, gamma),
        (&a_eval, &b_eval, &c_eval, &d_eval),
        (&left_sigma_eval, &right_sigma_eval, &out_sigma_eval),
        &perm_eval,
        z_poly,
    );

    let lin_poly = &f_1 + &f_2;

    // Evaluate linearisation polynomial at z_challenge
    let lin_poly_eval = lin_poly.evaluate(z_challenge);

    (
        lin_poly,
        Evaluations {
            proof: ProofEvaluations {
                a_eval,
                b_eval,
                c_eval,
                d_eval,
                a_next_eval,
                b_next_eval,
                d_next_eval,
                q_arith_eval,
                q_c_eval,
                left_sigma_eval,
                right_sigma_eval,
                out_sigma_eval,
                lin_poly_eval,
                perm_eval,
            },
            quot_eval,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_circuit_satisfiability(
    a_eval: &Scalar,
    b_eval: &Scalar,
    c_eval: &Scalar,
    d_eval: &Scalar,
    a_next_eval: &Scalar,
    b_next_eval: &Scalar,
    d_next_eval: &Scalar,
    q_arith_eval: &Scalar,
    q_c_eval: &Scalar,
    preprocessed_circuit: &PreProcessedCircuit,
) -> Polynomial {
    let a = preprocessed_circuit.arithmetic.compute_linearisation(
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        q_arith_eval,
    );

    let b = preprocessed_circuit.range.compute_linearisation(
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        &d_next_eval,
    );
    let c = preprocessed_circuit.logic.compute_linearisation(
        a_eval,
        a_next_eval,
        b_eval,
        b_next_eval,
        c_eval,
        d_eval,
        d_next_eval,
        q_c_eval,
    );
    &(&a + &b) + &c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn proof_evaluations_serde_roundtrip() {
        use bincode;
        let one = -Scalar::one();

        // Build directly the widget since there's not any `new()` impl
        // dor any other check and correctness methodology for the inputs.
        let proof_evals = ProofEvaluations {
            a_eval: one,
            b_eval: one,
            c_eval: one,
            d_eval: one,
            a_next_eval: one,
            b_next_eval: one,
            d_next_eval: one,
            q_arith_eval: one,
            q_c_eval: one,
            left_sigma_eval: one,
            right_sigma_eval: one,
            out_sigma_eval: one,
            lin_poly_eval: one,
            perm_eval: one,
        };

        // Roundtrip with evals
        let ser = bincode::serialize(&proof_evals).unwrap();
        let deser: ProofEvaluations = bincode::deserialize(&ser).unwrap();
        assert_eq!(proof_evals, deser);
    }
}
