// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A Proof stores the commitments to all of the elements that
//! are needed to univocally identify a prove of some statement.

use super::linearization_poly::ProofEvaluations;
use crate::commitment_scheme::Commitment;

use dusk_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "std")]
use rayon::prelude::*;

const V_MAX_DEGREE: usize = 7;

#[cfg(feature = "rkyv-impl")]
use crate::util::check_field;
#[cfg(feature = "rkyv-impl")]
use bytecheck::{CheckBytes, StructCheckError};
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

/// A Proof is a composition of `Commitment`s to the Witness, Permutation,
/// Quotient, Shifted and Opening polynomials as well as the
/// `ProofEvaluations`.
///
/// It's main goal is to allow the `Verifier` to formally verify that the secret
/// witnesses used to generate the [`Proof`] satisfy a circuit that both
/// [`Composer`] and [`Verifier`] have in common succintly and without any
/// capabilities of acquiring any kind of knowledge about the witness used to
/// construct the Proof.
///
/// [`Composer`]: [`crate::prelude::Composer`]
/// [`Verifier`]: [`crate::prelude::Verifier`]
#[derive(Debug, Eq, PartialEq, Clone, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace"))
)]
pub struct Proof {
    /// Commitment to the witness polynomial for the left wires.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_comm: Commitment,
    /// Commitment to the witness polynomial for the right wires.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_comm: Commitment,
    /// Commitment to the witness polynomial for the output wires.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) c_comm: Commitment,
    /// Commitment to the witness polynomial for the fourth wires.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_comm: Commitment,

    /// Commitment to the permutation polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) z_comm: Commitment,

    /// Commitment to the quotient polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_low_comm: Commitment,
    /// Commitment to the quotient polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_mid_comm: Commitment,
    /// Commitment to the quotient polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_high_comm: Commitment,
    /// Commitment to the quotient polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_fourth_comm: Commitment,

    /// Commitment to the opening polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) w_z_chall_comm: Commitment,
    /// Commitment to the shifted opening polynomial.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) w_z_chall_w_comm: Commitment,
    /// Subset of all of the evaluations added to the proof.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) evaluations: ProofEvaluations,
}

#[cfg(feature = "rkyv-impl")]
impl<C> CheckBytes<C> for ArchivedProof {
    type Error = StructCheckError;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        check_field(&(*value).a_comm, context, "a_comm")?;
        check_field(&(*value).b_comm, context, "b_comm")?;
        check_field(&(*value).c_comm, context, "c_comm")?;
        check_field(&(*value).d_comm, context, "d_comm")?;

        check_field(&(*value).z_comm, context, "z_comm")?;

        check_field(&(*value).t_low_comm, context, "t_low_comm")?;
        check_field(&(*value).t_mid_comm, context, "t_mid_comm")?;
        check_field(&(*value).t_high_comm, context, "t_high_comm")?;
        check_field(&(*value).t_fourth_comm, context, "t_fourth_comm")?;

        check_field(&(*value).w_z_chall_comm, context, "w_z_chall_comm")?;
        check_field(&(*value).w_z_chall_w_comm, context, "w_z_chall_w_comm")?;
        check_field(&(*value).evaluations, context, "evaluations")?;

        Ok(&*value)
    }
}

// The struct Proof has 11 commitments + 1 ProofEvaluations
impl Serializable<{ 11 * Commitment::SIZE + ProofEvaluations::SIZE }>
    for Proof
{
    type Error = dusk_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;

        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        writer.write(&self.a_comm.to_bytes());
        writer.write(&self.b_comm.to_bytes());
        writer.write(&self.c_comm.to_bytes());
        writer.write(&self.d_comm.to_bytes());
        writer.write(&self.z_comm.to_bytes());
        writer.write(&self.t_low_comm.to_bytes());
        writer.write(&self.t_mid_comm.to_bytes());
        writer.write(&self.t_high_comm.to_bytes());
        writer.write(&self.t_fourth_comm.to_bytes());
        writer.write(&self.w_z_chall_comm.to_bytes());
        writer.write(&self.w_z_chall_w_comm.to_bytes());
        writer.write(&self.evaluations.to_bytes());

        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut buffer = &buf[..];

        let a_comm = Commitment::from_reader(&mut buffer)?;
        let b_comm = Commitment::from_reader(&mut buffer)?;
        let c_comm = Commitment::from_reader(&mut buffer)?;
        let d_comm = Commitment::from_reader(&mut buffer)?;
        let z_comm = Commitment::from_reader(&mut buffer)?;
        let t_low_comm = Commitment::from_reader(&mut buffer)?;
        let t_mid_comm = Commitment::from_reader(&mut buffer)?;
        let t_high_comm = Commitment::from_reader(&mut buffer)?;
        let t_fourth_comm = Commitment::from_reader(&mut buffer)?;
        let w_z_chall_comm = Commitment::from_reader(&mut buffer)?;
        let w_z_chall_w_comm = Commitment::from_reader(&mut buffer)?;
        let evaluations = ProofEvaluations::from_reader(&mut buffer)?;

        Ok(Proof {
            a_comm,
            b_comm,
            c_comm,
            d_comm,
            z_comm,
            t_low_comm,
            t_mid_comm,
            t_high_comm,
            t_fourth_comm,
            w_z_chall_comm,
            w_z_chall_w_comm,
            evaluations,
        })
    }
}

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
pub(crate) mod alloc {
    use super::*;
    use crate::{
        commitment_scheme::{AggregateProof, OpeningKey},
        error::Error,
        fft::EvaluationDomain,
        proof_system::widget::VerifierKey,
        transcript::TranscriptProtocol,
        util::batch_inversion,
    };
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use dusk_bls12_381::{
        multiscalar_mul::msm_variable_base, BlsScalar, G1Affine, G1Projective,
    };
    use merlin::Transcript;
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    impl Proof {
        /// Performs the verification of a [`Proof`] returning a boolean result.
        #[allow(non_snake_case)]
        pub(crate) fn verify(
            &self,
            verifier_key: &VerifierKey,
            transcript: &mut Transcript,
            opening_key: &OpeningKey,
            pub_inputs: &[BlsScalar],
        ) -> Result<(), Error> {
            let domain = EvaluationDomain::new(verifier_key.n)?;

            // Subgroup checks are done when the proof is deserialized.

            // In order for the Verifier and Prover to have the same view in the
            // non-interactive setting Both parties must commit the same
            // elements into the transcript Below the verifier will simulate
            // an interaction with the prover by adding the same elements
            // that the prover added into the transcript, hence generating the
            // same challenges
            //
            // Add commitment to witness polynomials to transcript
            transcript.append_commitment(b"a_comm", &self.a_comm);
            transcript.append_commitment(b"b_comm", &self.b_comm);
            transcript.append_commitment(b"c_comm", &self.c_comm);
            transcript.append_commitment(b"d_comm", &self.d_comm);

            // Compute beta and gamma challenges
            let beta = transcript.challenge_scalar(b"beta");
            transcript.append_scalar(b"beta", &beta);
            let gamma = transcript.challenge_scalar(b"gamma");

            // Add commitment to permutation polynomial to transcript
            transcript.append_commitment(b"z_comm", &self.z_comm);

            // Compute quotient challenge
            let alpha = transcript.challenge_scalar(b"alpha");
            let range_sep_challenge =
                transcript.challenge_scalar(b"range separation challenge");
            let logic_sep_challenge =
                transcript.challenge_scalar(b"logic separation challenge");
            let fixed_base_sep_challenge =
                transcript.challenge_scalar(b"fixed base separation challenge");
            let var_base_sep_challenge = transcript
                .challenge_scalar(b"variable base separation challenge");

            // Add commitment to quotient polynomial to transcript
            transcript.append_commitment(b"t_low_comm", &self.t_low_comm);
            transcript.append_commitment(b"t_mid_comm", &self.t_mid_comm);
            transcript.append_commitment(b"t_high_comm", &self.t_high_comm);
            transcript.append_commitment(b"t_fourth_comm", &self.t_fourth_comm);

            // Compute evaluation challenge z
            let z_challenge = transcript.challenge_scalar(b"z_challenge");

            // Add opening evaluations to transcript
            transcript.append_scalar(b"a_eval", &self.evaluations.a_eval);
            transcript.append_scalar(b"b_eval", &self.evaluations.b_eval);
            transcript.append_scalar(b"c_eval", &self.evaluations.c_eval);
            transcript.append_scalar(b"d_eval", &self.evaluations.d_eval);

            transcript.append_scalar(
                b"s_sigma_1_eval",
                &self.evaluations.s_sigma_1_eval,
            );
            transcript.append_scalar(
                b"s_sigma_2_eval",
                &self.evaluations.s_sigma_2_eval,
            );
            transcript.append_scalar(
                b"s_sigma_3_eval",
                &self.evaluations.s_sigma_3_eval,
            );

            transcript.append_scalar(b"z_eval", &self.evaluations.z_eval);

            // Add extra shifted evaluations to transcript
            transcript.append_scalar(b"a_w_eval", &self.evaluations.a_w_eval);
            transcript.append_scalar(b"b_w_eval", &self.evaluations.b_w_eval);
            transcript.append_scalar(b"d_w_eval", &self.evaluations.d_w_eval);
            transcript
                .append_scalar(b"q_arith_eval", &self.evaluations.q_arith_eval);
            transcript.append_scalar(b"q_c_eval", &self.evaluations.q_c_eval);
            transcript.append_scalar(b"q_l_eval", &self.evaluations.q_l_eval);
            transcript.append_scalar(b"q_r_eval", &self.evaluations.q_r_eval);

            let v_challenge = transcript.challenge_scalar(b"v_challenge");
            let v_w_challenge = transcript.challenge_scalar(b"v_w_challenge");

            // Add commitment to openings to transcript
            transcript
                .append_commitment(b"w_z_chall_comm", &self.w_z_chall_comm);
            transcript
                .append_commitment(b"w_z_chall_w_comm", &self.w_z_chall_w_comm);

            // Compute the challenge 'u'
            let u_challenge = transcript.challenge_scalar(b"u_challenge");

            // Compute zero polynomial evaluated at challenge `z`
            let z_h_eval = domain.evaluate_vanishing_polynomial(&z_challenge);

            // Compute first lagrange polynomial evaluated at challenge `z`
            let l1_eval = compute_first_lagrange_evaluation(
                &domain,
                &z_h_eval,
                &z_challenge,
            );

            // Compute '[D]_1'
            let D = self
                .compute_linearization_commitment(
                    &alpha,
                    &beta,
                    &gamma,
                    (
                        &range_sep_challenge,
                        &logic_sep_challenge,
                        &fixed_base_sep_challenge,
                        &var_base_sep_challenge,
                    ),
                    &z_challenge,
                    &u_challenge,
                    l1_eval,
                    verifier_key,
                    &domain,
                )
                .0;

            // Evaluate public inputs
            let pi_eval =
                compute_barycentric_eval(pub_inputs, &z_challenge, &domain);

            // Compute r_0
            let r_0_eval = pi_eval
                - l1_eval * alpha.square()
                - alpha
                    * (self.evaluations.a_eval
                        + beta * self.evaluations.s_sigma_1_eval
                        + gamma)
                    * (self.evaluations.b_eval
                        + beta * self.evaluations.s_sigma_2_eval
                        + gamma)
                    * (self.evaluations.c_eval
                        + beta * self.evaluations.s_sigma_3_eval
                        + gamma)
                    * (self.evaluations.d_eval + gamma)
                    * self.evaluations.z_eval;

            // Coefficients to compute [E]_1
            let mut v_coeffs_E = vec![v_challenge];

            // Compute the powers of the v_challenge
            for i in 1..V_MAX_DEGREE {
                v_coeffs_E.push(v_coeffs_E[i - 1] * v_challenge);
            }

            // Compute the powers of the v_challenge multiplied by u_challenge
            v_coeffs_E.push(v_w_challenge * u_challenge);
            v_coeffs_E.push(v_coeffs_E[V_MAX_DEGREE] * v_w_challenge);
            v_coeffs_E.push(v_coeffs_E[V_MAX_DEGREE + 1] * v_w_challenge);

            // Evaluations to compute [E]_1
            let E_evals = vec![
                self.evaluations.a_eval,
                self.evaluations.b_eval,
                self.evaluations.c_eval,
                self.evaluations.d_eval,
                self.evaluations.s_sigma_1_eval,
                self.evaluations.s_sigma_2_eval,
                self.evaluations.s_sigma_3_eval,
                self.evaluations.a_w_eval,
                self.evaluations.b_w_eval,
                self.evaluations.d_w_eval,
            ];

            // Compute E = (-r_0 + (v)a + (v^2)b + (v^3)c + (v^4)d +
            // + (v^5)s_sigma_1 + (v^6)s_sigma_2 + (v^7)s_sigma_3 +
            // + (u)z_w + (u * v_w)a_w + (u * v_w^2)b_w + (u * v_w^3)d_w)
            let mut E_scalar: BlsScalar = E_evals
                .iter()
                .zip(v_coeffs_E.iter())
                .map(|(eval, coeff)| eval * coeff)
                .sum();
            E_scalar += -r_0_eval + (u_challenge * self.evaluations.z_eval);

            // We group all the remaining scalar multiplications in the
            // verification process, with the purpose of
            // parallelizing them
            let scalarmuls_points = vec![
                self.a_comm.0,
                self.b_comm.0,
                self.c_comm.0,
                self.d_comm.0,
                verifier_key.permutation.s_sigma_1.0,
                verifier_key.permutation.s_sigma_2.0,
                verifier_key.permutation.s_sigma_3.0,
                opening_key.g,
                self.w_z_chall_w_comm.0,
                self.w_z_chall_comm.0,
                self.w_z_chall_w_comm.0,
            ];

            let mut scalarmuls_scalars = v_coeffs_E[..V_MAX_DEGREE].to_vec();

            // As we include the shifted coefficients when computing [F]_1,
            // we group them to save scalar multiplications when multiplying
            // by [a]_1, [b]_1, and [d]_1
            scalarmuls_scalars[0] += v_coeffs_E[V_MAX_DEGREE];
            scalarmuls_scalars[1] += v_coeffs_E[V_MAX_DEGREE + 1];
            scalarmuls_scalars[3] += v_coeffs_E[V_MAX_DEGREE + 2];

            scalarmuls_scalars.push(E_scalar);
            scalarmuls_scalars.push(u_challenge);
            scalarmuls_scalars.push(z_challenge);
            scalarmuls_scalars
                .push(u_challenge * z_challenge * domain.group_gen);

            // Compute the scalar multiplications in single-core
            #[cfg(not(feature = "std"))]
            let scalarmuls: Vec<G1Projective> = scalarmuls_points
                .iter()
                .zip(scalarmuls_scalars.iter())
                .map(|(point, scalar)| point * scalar)
                .collect();

            // Compute the scalar multiplications in multi-core
            #[cfg(feature = "std")]
            let scalarmuls: Vec<G1Projective> = scalarmuls_points
                .par_iter()
                .zip(scalarmuls_scalars.par_iter())
                .map(|(point, scalar)| point * scalar)
                .collect();

            // [F]_1 = [D]_1 + (v)[a]_1 + (v^2)[b]_1 + (v^3)[c]_1 + (v^4)[d]_1 +
            // + (v^5)[s_sigma_1]_1 + (v^6)[s_sigma_2]_1 + (v^7)[s_sigma_3]_1 +
            // + (u * v_w)[a]_1 + (u * v_w^2)[b]_1 + (u * v_w^3)[d]_1
            let mut F: G1Projective = scalarmuls[..V_MAX_DEGREE].iter().sum();
            F += D;

            // [E]_1 = E * G
            let E = scalarmuls[V_MAX_DEGREE];

            // Compute the G_1 element of the first pairing:
            // [W_z]_1 + u * [W_zw]_1
            //
            // Note that we negate this value to be able to subtract
            // the pairings later on, using the multi Miller loop
            let left = G1Affine::from(
                -(self.w_z_chall_comm.0 + scalarmuls[V_MAX_DEGREE + 1]),
            );

            // Compute the G_1 element of the second pairing:
            // z * [W_z]_1 + (u * z * w) * [W_zw]_1 + [F]_1 - [E]_1
            let right = G1Affine::from(
                scalarmuls[V_MAX_DEGREE + 2] + scalarmuls[V_MAX_DEGREE + 3] + F
                    - E,
            );

            // Compute the two pairings and subtract them
            let pairing = dusk_bls12_381::multi_miller_loop(&[
                (&left, &opening_key.prepared_x_h),
                (&right, &opening_key.prepared_h),
            ])
            .final_exponentiation();

            // Return 'ProofVerificationError' if the two
            // pairings are not equal, continue otherwise
            if pairing != dusk_bls12_381::Gt::identity() {
                return Err(Error::ProofVerificationError);
            };

            Ok(())
        }

        // Commitment to [r]_1
        #[allow(clippy::too_many_arguments)]
        fn compute_linearization_commitment(
            &self,
            alpha: &BlsScalar,
            beta: &BlsScalar,
            gamma: &BlsScalar,
            (
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
            ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
            z_challenge: &BlsScalar,
            u_challenge: &BlsScalar,
            l1_eval: BlsScalar,
            verifier_key: &VerifierKey,
            domain: &EvaluationDomain,
        ) -> Commitment {
            let mut scalars: Vec<_> = Vec::with_capacity(6);
            let mut points: Vec<G1Affine> = Vec::with_capacity(6);

            verifier_key.arithmetic.compute_linearization_commitment(
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.range.compute_linearization_commitment(
                range_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.logic.compute_linearization_commitment(
                logic_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.fixed_base.compute_linearization_commitment(
                fixed_base_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.variable_base.compute_linearization_commitment(
                var_base_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.permutation.compute_linearization_commitment(
                &mut scalars,
                &mut points,
                &self.evaluations,
                z_challenge,
                u_challenge,
                (alpha, beta, gamma),
                &l1_eval,
                self.z_comm.0,
            );

            let domain_size = domain.size();
            let z_h_eval = -domain.evaluate_vanishing_polynomial(z_challenge);

            let z_n =
                z_challenge.pow(&[domain_size as u64, 0, 0, 0]) * z_h_eval;
            let z_two_n =
                z_challenge.pow(&[2 * domain_size as u64, 0, 0, 0]) * z_h_eval;
            let z_three_n =
                z_challenge.pow(&[3 * domain_size as u64, 0, 0, 0]) * z_h_eval;

            scalars.push(z_h_eval);
            points.push(self.t_low_comm.0);

            scalars.push(z_n);
            points.push(self.t_mid_comm.0);

            scalars.push(z_two_n);
            points.push(self.t_high_comm.0);

            scalars.push(z_three_n);
            points.push(self.t_fourth_comm.0);

            Commitment::from(msm_variable_base(&points, &scalars))
        }
    }

    fn compute_first_lagrange_evaluation(
        domain: &EvaluationDomain,
        z_h_eval: &BlsScalar,
        z_challenge: &BlsScalar,
    ) -> BlsScalar {
        let n_fr = BlsScalar::from(domain.size() as u64);
        let denom = n_fr * (z_challenge - BlsScalar::one());
        z_h_eval * denom.invert().unwrap()
    }

    pub(crate) fn compute_barycentric_eval(
        evaluations: &[BlsScalar],
        point: &BlsScalar,
        domain: &EvaluationDomain,
    ) -> BlsScalar {
        let numerator = (point.pow(&[domain.size() as u64, 0, 0, 0])
            - BlsScalar::one())
            * domain.size_inv;

        // Indices with non-zero evaluations
        #[cfg(not(feature = "std"))]
        let range = (0..evaluations.len()).into_iter();

        #[cfg(feature = "std")]
        let range = (0..evaluations.len()).into_par_iter();

        let non_zero_evaluations: Vec<usize> = range
            .filter(|&i| {
                let evaluation = &evaluations[i];
                evaluation != &BlsScalar::zero()
            })
            .collect();

        // Only compute the denominators with non-zero evaluations
        #[cfg(not(feature = "std"))]
        let range = (0..non_zero_evaluations.len()).into_iter();

        #[cfg(feature = "std")]
        let range = (0..non_zero_evaluations.len()).into_par_iter();

        let mut denominators: Vec<BlsScalar> = range
            .clone()
            .map(|i| {
                // index of non-zero evaluation
                let index = non_zero_evaluations[i];

                (domain.group_gen_inv.pow(&[index as u64, 0, 0, 0]) * point)
                    - BlsScalar::one()
            })
            .collect();
        batch_inversion(&mut denominators);

        let result: BlsScalar = range
            .map(|i| {
                let eval_index = non_zero_evaluations[i];
                let eval = evaluations[eval_index];

                denominators[i] * eval
            })
            .sum();

        result * numerator
    }
}

#[cfg(test)]
mod proof_tests {
    use super::*;
    use dusk_bls12_381::BlsScalar;
    use ff::Field;
    use rand_core::OsRng;

    #[test]
    fn test_dusk_bytes_serde_proof() {
        let proof = Proof {
            a_comm: Commitment::default(),
            b_comm: Commitment::default(),
            c_comm: Commitment::default(),
            d_comm: Commitment::default(),
            z_comm: Commitment::default(),
            t_low_comm: Commitment::default(),
            t_mid_comm: Commitment::default(),
            t_high_comm: Commitment::default(),
            t_fourth_comm: Commitment::default(),
            w_z_chall_comm: Commitment::default(),
            w_z_chall_w_comm: Commitment::default(),
            evaluations: ProofEvaluations {
                a_eval: BlsScalar::random(&mut OsRng),
                b_eval: BlsScalar::random(&mut OsRng),
                c_eval: BlsScalar::random(&mut OsRng),
                d_eval: BlsScalar::random(&mut OsRng),
                a_w_eval: BlsScalar::random(&mut OsRng),
                b_w_eval: BlsScalar::random(&mut OsRng),
                d_w_eval: BlsScalar::random(&mut OsRng),
                q_arith_eval: BlsScalar::random(&mut OsRng),
                q_c_eval: BlsScalar::random(&mut OsRng),
                q_l_eval: BlsScalar::random(&mut OsRng),
                q_r_eval: BlsScalar::random(&mut OsRng),
                s_sigma_1_eval: BlsScalar::random(&mut OsRng),
                s_sigma_2_eval: BlsScalar::random(&mut OsRng),
                s_sigma_3_eval: BlsScalar::random(&mut OsRng),
                z_eval: BlsScalar::random(&mut OsRng),
            },
        };

        let proof_bytes = proof.to_bytes();
        let got_proof = Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(got_proof, proof);
    }
}
