// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops;

use merlin::Transcript;
use rand_core::RngCore;
use sp_std::vec;
use zero_bls12_381::Fr as BlsScalar;
use zero_crypto::behave::FftField;
use zero_kzg::{Fft, Polynomial};

use crate::commitment_scheme::CommitKey;
use crate::error::Error;
use crate::fft::Polynomial as FftPolynomial;
use crate::proof_system::proof::Proof;
use crate::proof_system::{
    linearization_poly, quotient_poly, ProverKey, VerifierKey,
};
use crate::transcript::TranscriptProtocol;
use crate::util;

use super::{Builder, Circuit, Composer};

/// Turbo Prover with processed keys
#[derive(Clone)]
pub struct Prover<C>
where
    C: Circuit,
{
    pub(crate) prover_key: ProverKey,
    pub(crate) commit_key: CommitKey,
    pub(crate) transcript: Transcript,
    pub(crate) size: usize,
    pub(crate) constraints: usize,
    circuit: PhantomData<C>,
}

impl<C> ops::Deref for Prover<C>
where
    C: Circuit,
{
    type Target = ProverKey;

    fn deref(&self) -> &Self::Target {
        &self.prover_key
    }
}

impl<C> Prover<C>
where
    C: Circuit,
{
    pub(crate) fn new(
        label: Vec<u8>,
        prover_key: ProverKey,
        commit_key: CommitKey,
        verifier_key: VerifierKey,
        size: usize,
        constraints: usize,
    ) -> Self {
        let transcript =
            Transcript::base(label.as_slice(), &verifier_key, constraints);

        Self {
            prover_key,
            commit_key,
            transcript,
            size,
            constraints,
            circuit: PhantomData,
        }
    }

    /// adds blinding scalars to a witness vector
    ///
    /// appends:
    ///
    /// if hiding degree = 1: (b2*X^(n+1) + b1*X^n - b2*X - b1) + witnesses
    /// if hiding degree = 2: (b3*X^(n+2) + b2*X^(n+1) + b1*X^n - b3*X^2 - b2*X
    fn blind_poly<R>(
        rng: &mut R,
        witnesses: &[BlsScalar],
        hiding_degree: usize,
        fft: &Fft<BlsScalar>,
    ) -> FftPolynomial
    where
        R: RngCore,
    {
        let mut w_vec_inverse = Polynomial::new(witnesses.to_vec());
        fft.idft(&mut w_vec_inverse);

        for i in 0..hiding_degree + 1 {
            let blinding_scalar = util::random_scalar(rng);

            w_vec_inverse.0[i] = w_vec_inverse.0[i] - blinding_scalar;
            w_vec_inverse.0.push(blinding_scalar);
        }

        FftPolynomial::from_coefficients_vec(w_vec_inverse.0)
    }

    /// Prove the circuit
    pub fn prove<R>(
        &self,
        rng: &mut R,
        circuit: &C,
    ) -> Result<(Proof, Vec<BlsScalar>), Error>
    where
        C: Circuit,
        R: RngCore,
    {
        let prover = Builder::prove(self.constraints, circuit)?;

        let size = self.size;
        let k = size.trailing_zeros();

        let fft = Fft::<BlsScalar>::new(k as usize);

        let mut transcript = self.transcript.clone();

        let public_inputs = prover.public_inputs();
        let public_input_indexes = prover.public_input_indexes();
        let mut dense_public_inputs =
            Polynomial::new(Builder::dense_public_inputs(
                &public_input_indexes,
                &public_inputs,
                self.size,
            ));

        public_inputs
            .iter()
            .for_each(|pi| transcript.append_scalar(b"pi", pi));

        // round 1
        // convert wires to padded scalars
        let mut a_w_scalar = vec![BlsScalar::zero(); size];
        let mut b_w_scalar = vec![BlsScalar::zero(); size];
        let mut o_w_scalar = vec![BlsScalar::zero(); size];
        let mut d_w_scalar = vec![BlsScalar::zero(); size];

        prover.constraints.iter().enumerate().for_each(|(i, c)| {
            a_w_scalar[i] = prover[c.w_a];
            b_w_scalar[i] = prover[c.w_b];
            o_w_scalar[i] = prover[c.w_o];
            d_w_scalar[i] = prover[c.w_d];
        });

        let a_w_poly = Self::blind_poly(rng, &a_w_scalar, 1, &fft);
        let b_w_poly = Self::blind_poly(rng, &b_w_scalar, 1, &fft);
        let o_w_poly = Self::blind_poly(rng, &o_w_scalar, 1, &fft);
        let d_w_poly = Self::blind_poly(rng, &d_w_scalar, 1, &fft);

        // commit to wire polynomials
        // ([a(x)]_1, [b(x)]_1, [c(x)]_1, [d(x)]_1)
        let a_w_poly_commit = self.commit_key.commit(&a_w_poly)?;
        let b_w_poly_commit = self.commit_key.commit(&b_w_poly)?;
        let o_w_poly_commit = self.commit_key.commit(&o_w_poly)?;
        let d_w_poly_commit = self.commit_key.commit(&d_w_poly)?;

        // Add wire polynomial commitments to transcript
        transcript.append_commitment(b"a_w", &a_w_poly_commit);
        transcript.append_commitment(b"b_w", &b_w_poly_commit);
        transcript.append_commitment(b"c_w", &o_w_poly_commit);
        transcript.append_commitment(b"d_w", &d_w_poly_commit);

        // round 2
        // permutation challenges
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);

        let gamma = transcript.challenge_scalar(b"gamma");
        let sigma = [
            Polynomial::new(
                self.prover_key.permutation.s_sigma_1.0.coeffs.clone(),
            ),
            Polynomial::new(
                self.prover_key.permutation.s_sigma_2.0.coeffs.clone(),
            ),
            Polynomial::new(
                self.prover_key.permutation.s_sigma_3.0.coeffs.clone(),
            ),
            Polynomial::new(
                self.prover_key.permutation.s_sigma_4.0.coeffs.clone(),
            ),
        ];
        let wires = [
            a_w_scalar.as_slice(),
            b_w_scalar.as_slice(),
            o_w_scalar.as_slice(),
            d_w_scalar.as_slice(),
        ];
        let permutation = prover
            .perm
            .compute_permutation_vec(&fft, wires, &beta, &gamma, sigma);

        let z_poly = Self::blind_poly(rng, &permutation, 2, &fft);
        let z_poly_commit = self.commit_key.commit(&z_poly)?;
        transcript.append_commitment(b"z", &z_poly_commit);

        // round 3
        // compute quotient challenge alpha
        let alpha = transcript.challenge_scalar(b"alpha");
        let range_sep_challenge =
            transcript.challenge_scalar(b"range separation challenge");
        let logic_sep_challenge =
            transcript.challenge_scalar(b"logic separation challenge");
        let fixed_base_sep_challenge =
            transcript.challenge_scalar(b"fixed base separation challenge");
        let var_base_sep_challenge =
            transcript.challenge_scalar(b"variable base separation challenge");

        // compute public inputs polynomial
        fft.idft(&mut dense_public_inputs);
        let pi_poly =
            FftPolynomial::from_coefficients_vec(dense_public_inputs.0);

        // compute quotient polynomial
        let wires = (&a_w_poly, &b_w_poly, &o_w_poly, &d_w_poly);
        let args = &(
            alpha,
            beta,
            gamma,
            range_sep_challenge,
            logic_sep_challenge,
            fixed_base_sep_challenge,
            var_base_sep_challenge,
        );
        let t_poly = quotient_poly::compute(
            &fft,
            &self.prover_key,
            &z_poly,
            wires,
            &pi_poly,
            args,
        )?;

        // split quotient polynomial into 4 degree `n` polynomials
        let domain_size = fft.size();
        let t_low_poly = FftPolynomial::from_coefficients_vec(
            t_poly[0..domain_size].to_vec(),
        );
        let t_mid_poly = FftPolynomial::from_coefficients_vec(
            t_poly[domain_size..2 * domain_size].to_vec(),
        );
        let t_high_poly = FftPolynomial::from_coefficients_vec(
            t_poly[2 * domain_size..3 * domain_size].to_vec(),
        );
        let t_4_poly = FftPolynomial::from_coefficients_vec(
            t_poly[3 * domain_size..].to_vec(),
        );

        // commit to split quotient polynomial
        let t_low_commit = self.commit_key.commit(&t_low_poly)?;
        let t_mid_commit = self.commit_key.commit(&t_mid_poly)?;
        let t_high_commit = self.commit_key.commit(&t_high_poly)?;
        let t_4_commit = self.commit_key.commit(&t_4_poly)?;

        // add quotient polynomial commitments to transcript
        transcript.append_commitment(b"t_low", &t_low_commit);
        transcript.append_commitment(b"t_mid", &t_mid_commit);
        transcript.append_commitment(b"t_high", &t_high_commit);
        transcript.append_commitment(b"t_4", &t_4_commit);

        // round 4
        // compute evaluation challenge 'z'
        let z_challenge = transcript.challenge_scalar(b"z_challenge");

        // round 5
        // compute linearization polynomial
        let (r_poly, evaluations) = linearization_poly::compute(
            fft.generator(),
            &self.prover_key,
            &(
                alpha,
                beta,
                gamma,
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
                z_challenge,
            ),
            &a_w_poly,
            &b_w_poly,
            &o_w_poly,
            &d_w_poly,
            &t_poly,
            &z_poly,
        );

        // add evaluations to transcript.
        transcript.append_scalar(b"a_eval", &evaluations.proof.a_eval);
        transcript.append_scalar(b"b_eval", &evaluations.proof.b_eval);
        transcript.append_scalar(b"c_eval", &evaluations.proof.c_eval);
        transcript.append_scalar(b"d_eval", &evaluations.proof.d_eval);
        transcript
            .append_scalar(b"a_next_eval", &evaluations.proof.a_next_eval);
        transcript
            .append_scalar(b"b_next_eval", &evaluations.proof.b_next_eval);
        transcript
            .append_scalar(b"d_next_eval", &evaluations.proof.d_next_eval);
        transcript.append_scalar(
            b"s_sigma_1_eval",
            &evaluations.proof.s_sigma_1_eval,
        );
        transcript.append_scalar(
            b"s_sigma_2_eval",
            &evaluations.proof.s_sigma_2_eval,
        );
        transcript.append_scalar(
            b"s_sigma_3_eval",
            &evaluations.proof.s_sigma_3_eval,
        );
        transcript
            .append_scalar(b"q_arith_eval", &evaluations.proof.q_arith_eval);
        transcript.append_scalar(b"q_c_eval", &evaluations.proof.q_c_eval);
        transcript.append_scalar(b"q_l_eval", &evaluations.proof.q_l_eval);
        transcript.append_scalar(b"q_r_eval", &evaluations.proof.q_r_eval);
        transcript.append_scalar(b"perm_eval", &evaluations.proof.perm_eval);
        transcript.append_scalar(b"t_eval", &evaluations.t_eval);
        transcript.append_scalar(b"r_eval", &evaluations.proof.r_poly_eval);

        // compute Openings using KZG10
        let z_n = z_challenge.pow(domain_size as u64);
        let z_two_n = z_challenge.pow(2 * domain_size as u64);
        let z_three_n = z_challenge.pow(3 * domain_size as u64);

        let a = &t_low_poly;
        let b = &t_mid_poly * &z_n;
        let c = &t_high_poly * &z_two_n;
        let d = &t_4_poly * &z_three_n;
        let abc = &(a + &b) + &c;

        let quot = &abc + &d;

        // compute aggregate witness to polynomials evaluated at the evaluation
        // challenge z. The challenge v is selected inside
        let aggregate_witness = self.commit_key.compute_aggregate_witness(
            &[
                quot,
                r_poly,
                a_w_poly.clone(),
                b_w_poly.clone(),
                o_w_poly,
                d_w_poly.clone(),
                self.prover_key.permutation.s_sigma_1.0.clone(),
                self.prover_key.permutation.s_sigma_2.0.clone(),
                self.prover_key.permutation.s_sigma_3.0.clone(),
            ],
            &z_challenge,
            &mut transcript,
        );
        let w_z_chall_comm = self.commit_key.commit(&aggregate_witness)?;

        // compute aggregate witness to polynomials evaluated at the shifted
        // evaluation challenge
        let shifted_aggregate_witness =
            self.commit_key.compute_aggregate_witness(
                &[z_poly, a_w_poly, b_w_poly, d_w_poly],
                &(z_challenge * fft.generator()),
                &mut transcript,
            );
        let w_z_chall_w_comm =
            self.commit_key.commit(&shifted_aggregate_witness)?;

        let proof = Proof {
            a_comm: a_w_poly_commit,
            b_comm: b_w_poly_commit,
            c_comm: o_w_poly_commit,
            d_comm: d_w_poly_commit,

            z_comm: z_poly_commit,

            t_low_comm: t_low_commit,
            t_mid_comm: t_mid_commit,
            t_high_comm: t_high_commit,
            t_4_comm: t_4_commit,

            w_z_chall_comm,
            w_z_chall_w_comm,

            evaluations: evaluations.proof,
        };

        Ok((proof, public_inputs))
    }
}
