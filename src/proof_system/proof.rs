//! A Proof stores the commitments to all of the elements that
//! are needed to univocally identify a prove of some statement.
//!
//! This module contains the implementation of the `StandardComposer`s
//! `Proof` structure and it's methods.

use super::linearisation_poly::ProofEvaluations;
use super::proof_system_errors::{ProofError, ProofErrors};
use super::PreProcessedCircuit;
use crate::commitment_scheme::kzg10::AggregateProof;
use crate::commitment_scheme::kzg10::{Commitment, OpeningKey};
use crate::fft::EvaluationDomain;
use crate::transcript::TranscriptProtocol;
use dusk_bls12_381::{multiscalar_mul::msm_variable_base, G1Affine, Scalar};
use failure::Error;
#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Eq, PartialEq)]
/// A Proof is a composition of `Commitments` to the witness, permutation,
/// quotient, shifted and opening polynomials as well as the
/// `ProofEvaluations`.
///
/// It's main goal is to have a `verify()` method attached which contains the
/// logic of the operations that the `Verifier` will need to do in order to
/// formally verify the `Proof`.
pub struct Proof {
    /// Commitment to the witness polynomial for the left wires.
    pub a_comm: Commitment,
    /// Commitment to the witness polynomial for the right wires.
    pub b_comm: Commitment,
    /// Commitment to the witness polynomial for the output wires.
    pub c_comm: Commitment,
    /// Commitment to the witness polynomial for the fourth wires.
    pub d_comm: Commitment,

    /// Commitment to the permutation polynomial.
    pub z_comm: Commitment,

    /// Commitment to the quotient polynomial.
    pub t_1_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_2_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_3_comm: Commitment,
    /// Commitment to the quotient polynomial.
    pub t_4_comm: Commitment,

    /// Commitment to the opening polynomial.
    pub w_z_comm: Commitment,
    /// Commitment to the shifted opening polynomial.
    pub w_zw_comm: Commitment,
    /// Subset of all of the evaluations added to the proof.
    pub evaluations: ProofEvaluations,
}

#[cfg(feature = "serde")]
impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut proof = serializer.serialize_struct("struct Proof", 12)?;
        proof.serialize_field("a_comm", &self.a_comm)?;
        proof.serialize_field("b_comm", &self.b_comm)?;
        proof.serialize_field("c_comm", &self.c_comm)?;
        proof.serialize_field("d_comm", &self.d_comm)?;
        proof.serialize_field("z_comm", &self.z_comm)?;
        proof.serialize_field("t_1_comm", &self.t_1_comm)?;
        proof.serialize_field("t_2_comm", &self.t_2_comm)?;
        proof.serialize_field("t_3_comm", &self.t_3_comm)?;
        proof.serialize_field("t_4_comm", &self.t_4_comm)?;
        proof.serialize_field("w_z_comm", &self.w_z_comm)?;
        proof.serialize_field("w_zw_comm", &self.w_zw_comm)?;
        proof.serialize_field("evaluations", &self.evaluations)?;
        proof.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Acomm,
            Bcomm,
            Ccomm,
            Dcomm,
            Zcomm,
            T1comm,
            T2comm,
            T3comm,
            T4comm,
            WZcomm,
            WZWcomm,
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
                        formatter.write_str("struct Proof")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "a_comm" => Ok(Field::Acomm),
                            "b_comm" => Ok(Field::Bcomm),
                            "c_comm" => Ok(Field::Ccomm),
                            "d_comm" => Ok(Field::Dcomm),
                            "z_comm" => Ok(Field::Zcomm),
                            "t_1_comm" => Ok(Field::T1comm),
                            "t_2_comm" => Ok(Field::T2comm),
                            "t_3_comm" => Ok(Field::T3comm),
                            "t_4_comm" => Ok(Field::T4comm),
                            "w_z_comm" => Ok(Field::WZcomm),
                            "w_zw_comm" => Ok(Field::WZWcomm),
                            "evaluations" => Ok(Field::Evals),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ProofVisitor;

        impl<'de> Visitor<'de> for ProofVisitor {
            type Value = Proof;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct Proof")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Proof, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let a_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let b_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let c_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let d_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let z_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let t_1_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let t_2_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let t_3_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let t_4_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let w_z_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let w_zw_comm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let evaluations = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(Proof {
                    a_comm,
                    b_comm,
                    c_comm,
                    d_comm,
                    z_comm,
                    t_1_comm,
                    t_2_comm,
                    t_3_comm,
                    t_4_comm,
                    w_z_comm,
                    w_zw_comm,
                    evaluations,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "a_comm",
            "b_comm",
            "c_comm",
            "d_comm",
            "z_comm",
            "t_1_comm",
            "t_2_comm",
            "t_3_comm",
            "t_4_comm",
            "w_z_comm",
            "w_zw_comm",
            "evaluations",
        ];
        deserializer.deserialize_struct("Proof", FIELDS, ProofVisitor)
    }
}

impl Proof {
    /// Performs the verification of a `Proof` returning a boolean result.
    pub fn verify(
        &self,
        preprocessed_circuit: &PreProcessedCircuit,
        transcript: &mut dyn TranscriptProtocol,
        opening_key: &OpeningKey,
        pub_inputs: &[Scalar],
    ) -> Result<(), Error> {
        let domain = EvaluationDomain::new(preprocessed_circuit.n)?;

        // Subgroup checks are done when the proof is deserialised.

        // In order for the Verifier and Prover to have the same view in the non-interactive setting
        // Both parties must commit the same elements into the transcript
        // Below the verifier will simulate an interaction with the prover by adding the same elements
        // that the prover added into the transcript, hence generating the same challenges
        //
        // Add commitment to witness polynomials to transcript
        transcript.append_commitment(b"w_l", &self.a_comm);
        transcript.append_commitment(b"w_r", &self.b_comm);
        transcript.append_commitment(b"w_o", &self.c_comm);
        transcript.append_commitment(b"w_4", &self.d_comm);

        // Compute beta and gamma challenges
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");
        // Add commitment to permutation polynomial to transcript
        transcript.append_commitment(b"z", &self.z_comm);

        // Compute quotient challenge
        let alpha = transcript.challenge_scalar(b"alpha");

        // Add commitment to quotient polynomial to transcript
        transcript.append_commitment(b"t_1", &self.t_1_comm);
        transcript.append_commitment(b"t_2", &self.t_2_comm);
        transcript.append_commitment(b"t_3", &self.t_3_comm);
        transcript.append_commitment(b"t_4", &self.t_4_comm);

        // Compute evaluation challenge
        let z_challenge = transcript.challenge_scalar(b"z");

        // Compute zero polynomial evaluated at `z_challenge`
        let z_h_eval = domain.evaluate_vanishing_polynomial(&z_challenge);

        // Compute first lagrange polynomial evaluated at `z_challenge`
        let l1_eval = compute_first_lagrange_evaluation(&domain, &z_h_eval, &z_challenge);

        // Compute quotient polynomial evaluated at `z_challenge`
        let t_eval = self.compute_quotient_evaluation(
            &domain,
            pub_inputs,
            &alpha,
            &beta,
            &gamma,
            &z_challenge,
            &z_h_eval,
            &l1_eval,
            &self.evaluations.perm_eval,
        );

        // Compute commitment to quotient polynomial
        // This method is necessary as we pass the `un-splitted` variation to our commitment scheme
        let t_comm = self.compute_quotient_commitment(&z_challenge, domain.size());

        // Add evaluations to transcript
        transcript.append_scalar(b"a_eval", &self.evaluations.a_eval);
        transcript.append_scalar(b"b_eval", &self.evaluations.b_eval);
        transcript.append_scalar(b"c_eval", &self.evaluations.c_eval);
        transcript.append_scalar(b"d_eval", &self.evaluations.d_eval);
        transcript.append_scalar(b"a_next_eval", &self.evaluations.a_next_eval);
        transcript.append_scalar(b"b_next_eval", &self.evaluations.b_next_eval);
        transcript.append_scalar(b"d_next_eval", &self.evaluations.d_next_eval);
        transcript.append_scalar(b"left_sig_eval", &self.evaluations.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &self.evaluations.right_sigma_eval);
        transcript.append_scalar(b"out_sig_eval", &self.evaluations.out_sigma_eval);
        transcript.append_scalar(b"q_arith_eval", &self.evaluations.q_arith_eval);
        transcript.append_scalar(b"q_c_eval", &self.evaluations.q_c_eval);
        transcript.append_scalar(b"perm_eval", &self.evaluations.perm_eval);
        transcript.append_scalar(b"t_eval", &t_eval);
        transcript.append_scalar(b"r_eval", &self.evaluations.lin_poly_eval);

        // Compute linearisation commitment
        let r_comm = self.compute_linearisation_commitment(
            &alpha,
            &beta,
            &gamma,
            &z_challenge,
            l1_eval,
            &preprocessed_circuit,
        );

        // Commitment Scheme
        // Now we delegate computation to the commitment scheme by batch checking two proofs
        // The `AggregateProof`, which is a proof that all the necessary polynomials evaluated at `z_challenge` are correct
        // and a `SingleProof` which is proof that the permutation polynomial evaluated at the shifted root of unity is correct

        // Compose the Aggregated Proof
        //
        let mut aggregate_proof = AggregateProof::with_witness(self.w_z_comm);
        aggregate_proof.add_part((t_eval, t_comm));
        aggregate_proof.add_part((self.evaluations.lin_poly_eval, r_comm));
        aggregate_proof.add_part((self.evaluations.a_eval, self.a_comm));
        aggregate_proof.add_part((self.evaluations.b_eval, self.b_comm));
        aggregate_proof.add_part((self.evaluations.c_eval, self.c_comm));
        aggregate_proof.add_part((self.evaluations.d_eval, self.d_comm));
        aggregate_proof.add_part((
            self.evaluations.left_sigma_eval,
            preprocessed_circuit.permutation.left_sigma.commitment,
        ));
        aggregate_proof.add_part((
            self.evaluations.right_sigma_eval,
            preprocessed_circuit.permutation.right_sigma.commitment,
        ));
        aggregate_proof.add_part((
            self.evaluations.out_sigma_eval,
            preprocessed_circuit.permutation.out_sigma.commitment,
        ));
        // Flatten proof with opening challenge
        let flattened_proof_a = aggregate_proof.flatten(transcript);

        // Compose the shifted aggregate proof
        let mut shifted_aggregate_proof = AggregateProof::with_witness(self.w_zw_comm);
        shifted_aggregate_proof.add_part((self.evaluations.perm_eval, self.z_comm));
        shifted_aggregate_proof.add_part((self.evaluations.a_next_eval, self.a_comm));
        shifted_aggregate_proof.add_part((self.evaluations.b_next_eval, self.b_comm));
        shifted_aggregate_proof.add_part((self.evaluations.d_next_eval, self.d_comm));
        let flattened_proof_b = shifted_aggregate_proof.flatten(transcript);

        // Add commitment to openings to transcript
        transcript.append_commitment(b"w_z", &self.w_z_comm);
        transcript.append_commitment(b"w_z_w", &self.w_zw_comm);

        // Batch check
        if opening_key
            .batch_check(
                &[z_challenge, (z_challenge * domain.group_gen)],
                &[flattened_proof_a, flattened_proof_b],
                transcript,
            )
            .is_err()
        {
            return Err(ProofError(ProofErrors::ProofVerificationError.into()).into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_quotient_evaluation(
        &self,
        domain: &EvaluationDomain,
        pub_inputs: &[Scalar],
        alpha: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
        z_challenge: &Scalar,
        z_h_eval: &Scalar,
        l1_eval: &Scalar,
        z_hat_eval: &Scalar,
    ) -> Scalar {
        // Compute the public input polynomial evaluated at `z_challenge`
        let pi_eval = compute_barycentric_eval(pub_inputs, z_challenge, domain);

        let alpha_sq = alpha.square();

        // r + PI(z)
        let a = self.evaluations.lin_poly_eval + pi_eval;

        // a + beta * sigma_1 + gamma
        let beta_sig1 = beta * self.evaluations.left_sigma_eval;
        let b_0 = self.evaluations.a_eval + beta_sig1 + gamma;

        // b+ beta * sigma_2 + gamma
        let beta_sig2 = beta * self.evaluations.right_sigma_eval;
        let b_1 = self.evaluations.b_eval + beta_sig2 + gamma;

        // c+ beta * sigma_3 + gamma
        let beta_sig3 = beta * self.evaluations.out_sigma_eval;
        let b_2 = self.evaluations.c_eval + beta_sig3 + gamma;

        // ((d + gamma) * z_hat) * alpha
        let b_3 = (self.evaluations.d_eval + gamma) * z_hat_eval * alpha;

        let b = b_0 * b_1 * b_2 * b_3;

        // l_1(z) * alpha^2
        let c = l1_eval * alpha_sq;

        // Return t_eval
        (a - b - c) * z_h_eval.invert().unwrap()
    }

    fn compute_quotient_commitment(&self, z_challenge: &Scalar, n: usize) -> Commitment {
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
        let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);
        let t_comm = self.t_1_comm.0
            + self.t_2_comm.0 * z_n
            + self.t_3_comm.0 * z_two_n
            + self.t_4_comm.0 * z_three_n;
        Commitment::from_projective(t_comm)
    }

    // Commitment to [r]_1
    fn compute_linearisation_commitment(
        &self,
        alpha: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
        z_challenge: &Scalar,
        l1_eval: Scalar,
        preprocessed_circuit: &PreProcessedCircuit,
    ) -> Commitment {
        let mut scalars: Vec<_> = Vec::with_capacity(6);
        let mut points: Vec<G1Affine> = Vec::with_capacity(6);

        preprocessed_circuit
            .arithmetic
            .compute_linearisation_commitment(&mut scalars, &mut points, &self.evaluations);

        preprocessed_circuit.range.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
        );

        preprocessed_circuit.logic.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
        );

        preprocessed_circuit
            .permutation
            .compute_linearisation_commitment(
                &mut scalars,
                &mut points,
                &self.evaluations,
                z_challenge,
                (alpha, beta, gamma),
                &l1_eval,
                self.z_comm.0,
            );

        Commitment::from_projective(msm_variable_base(&points, &scalars))
    }
}

fn compute_first_lagrange_evaluation(
    domain: &EvaluationDomain,
    z_h_eval: &Scalar,
    z_challenge: &Scalar,
) -> Scalar {
    let n_fr = Scalar::from(domain.size() as u64);
    let denom = n_fr * (z_challenge - Scalar::one());
    z_h_eval * denom.invert().unwrap()
}

#[warn(clippy::needless_range_loop)]
fn compute_barycentric_eval(
    evaluations: &[Scalar],
    point: &Scalar,
    domain: &EvaluationDomain,
) -> Scalar {
    use crate::util::batch_inversion;
    use rayon::iter::IntoParallelIterator;
    use rayon::prelude::*;

    let numerator = (point.pow(&[domain.size() as u64, 0, 0, 0]) - Scalar::one()) * domain.size_inv;

    // Indices with non-zero evaluations
    let non_zero_evaluations: Vec<usize> = (0..evaluations.len())
        .into_par_iter()
        .filter(|&i| {
            let evaluation = &evaluations[i];
            evaluation != &Scalar::zero()
        })
        .collect();

    // Only compute the denominators with non-zero evaluations
    let mut denominators: Vec<Scalar> = (0..non_zero_evaluations.len())
        .into_par_iter()
        .map(|i| {
            // index of non-zero evaluation
            let index = non_zero_evaluations[i];

            (domain.group_gen_inv.pow(&[index as u64, 0, 0, 0]) * point) - Scalar::one()
        })
        .collect();
    batch_inversion(&mut denominators);

    let result: Scalar = (0..non_zero_evaluations.len())
        .into_par_iter()
        .map(|i| {
            let eval_index = non_zero_evaluations[i];
            let eval = evaluations[eval_index];

            denominators[i] * eval
        })
        .sum();

    result * numerator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "serde")]
    #[test]
    fn proof_serde_roundtrip() {
        use bincode;
        let comm = Commitment::empty();
        let one = Scalar::one();

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

        // Build directly the widget since there's not any `new()` impl
        // dor any other check and correctness methodology for the inputs.
        let proof = Proof {
            a_comm: comm,
            b_comm: comm,
            c_comm: comm,
            d_comm: comm,
            z_comm: comm,
            t_1_comm: comm,
            t_2_comm: comm,
            t_3_comm: comm,
            t_4_comm: comm,
            w_z_comm: comm,
            w_zw_comm: comm,
            evaluations: proof_evals,
        };

        // Roundtrip with evals
        let ser = bincode::serialize(&proof).unwrap();
        let deser: Proof = bincode::deserialize(&ser).unwrap();
        assert_eq!(proof, deser);
    }
}
