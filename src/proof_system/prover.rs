// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{
    commitment_scheme::CommitKey,
    constraint_system::{TurboComposer, Witness},
    error::Error,
    fft::{EvaluationDomain, Polynomial},
    proof_system::{
        linearization_poly, proof::Proof, quotient_poly, ProverKey,
    },
    transcript::TranscriptProtocol,
    util,
};
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

/// Abstraction structure designed to construct a circuit and generate
/// [`Proof`]s for it.
#[allow(missing_debug_implementations)]
pub struct Prover {
    /// ProverKey which is used to create proofs about a specific PLONK circuit
    pub prover_key: Option<ProverKey>,

    pub(crate) cs: TurboComposer,
    /// Store the messages exchanged during the preprocessing stage
    /// This is copied each time, we make a proof
    pub preprocessed_transcript: Transcript,
}

impl Prover {
    /// Mutable borrow of [`TurboComposer`].
    pub fn composer_mut(&mut self) -> &mut TurboComposer {
        &mut self.cs
    }

    /// Preprocesses the underlying constraint system.
    pub fn preprocess(&mut self, commit_key: &CommitKey) -> Result<(), Error> {
        if self.prover_key.is_some() {
            return Err(Error::CircuitAlreadyPreprocessed);
        }
        let pk = self
            .cs
            .preprocess_prover(commit_key, &mut self.preprocessed_transcript)?;
        self.prover_key = Some(pk);
        Ok(())
    }
}

impl Default for Prover {
    fn default() -> Prover {
        Prover::new(b"plonk")
    }
}

impl Prover {
    /// Creates a new `Prover` instance.
    pub fn new(label: &'static [u8]) -> Prover {
        Prover {
            prover_key: None,
            cs: TurboComposer::new(),
            preprocessed_transcript: Transcript::new(label),
        }
    }

    /// Creates a new `Prover` object with some expected size.
    pub fn with_size(label: &'static [u8], size: usize) -> Prover {
        Prover {
            prover_key: None,
            cs: TurboComposer::with_size(size),
            preprocessed_transcript: Transcript::new(label),
        }
    }

    /// Returns the number of gates in the circuit thet the `Prover` actually
    /// stores inside.
    pub const fn gates(&self) -> usize {
        self.cs.gates()
    }

    /// Split `t(X)` poly into 4 degree `n` polynomials.
    pub(crate) fn split_tx_poly(
        &self,
        n: usize,
        t_x: &Polynomial,
    ) -> (Polynomial, Polynomial, Polynomial, Polynomial) {
        (
            Polynomial::from_coefficients_vec(t_x[0..n].to_vec()),
            Polynomial::from_coefficients_vec(t_x[n..2 * n].to_vec()),
            Polynomial::from_coefficients_vec(t_x[2 * n..3 * n].to_vec()),
            Polynomial::from_coefficients_vec(t_x[3 * n..].to_vec()),
        )
    }

    /// Computes the quotient Opening [`Polynomial`].
    fn compute_quotient_opening_poly(
        n: usize,
        t_low_poly: &Polynomial,
        t_mid_poly: &Polynomial,
        t_high_poly: &Polynomial,
        t_4_poly: &Polynomial,
        z_challenge: &BlsScalar,
    ) -> Polynomial {
        // Compute z^n , z^2n , z^3n
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
        let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);

        let a = t_low_poly;
        let b = t_mid_poly * &z_n;
        let c = t_high_poly * &z_two_n;
        let d = t_4_poly * &z_three_n;
        let abc = &(a + &b) + &c;
        &abc + &d
    }

    /// Convert witnesses to their actual witness values.
    pub(crate) fn to_scalars(&self, vars: &[Witness]) -> Vec<BlsScalar> {
        vars.iter().map(|var| self.cs.witnesses[var]).collect()
    }

    /// Resets the witnesses in the prover object.
    /// This function is used when the user wants to make multiple proofs with
    /// the same circuit.
    pub fn clear_witness(&mut self) {
        self.cs = TurboComposer::new();
    }

    /// Clears all data in the `Prover` instance.
    /// This function is used when the user wants to use the same `Prover` to
    /// make a [`Proof`] regarding a different circuit.
    pub fn clear(&mut self) {
        self.clear_witness();
        self.prover_key = None;
        self.preprocessed_transcript = Transcript::new(b"plonk");
    }

    /// Keys the [`Transcript`] with additional seed information
    /// Wrapper around [`Transcript::append_message`].
    pub fn key_transcript(&mut self, label: &'static [u8], message: &[u8]) {
        self.preprocessed_transcript.append_message(label, message);
    }

    /// Adds the blinding scalars to a given vector. Always the same elements
    /// of 'w_vec' are modified at the beginning of it, and appended at the end:
    /// if hiding degree = 1: (b2*X^(n+1) + b1*X^n - b2*X - b1) + w_vec
    /// if hiding degree = 2: (b3*X^(n+2) + b2*X^(n+1) + b1*X^n - b3*X^2 - b2*X
    /// - b1) + w_vec
    pub(crate) fn blind_poly<R: RngCore + CryptoRng>(
        w_vec: &Vec<BlsScalar>,
        hiding_degree: usize,
        domain: &EvaluationDomain,
        rng: &mut R,
    ) -> Polynomial {
        let mut w_vec_inverse = domain.ifft(w_vec);

        for i in 0..hiding_degree + 1 {
            // we declare and randomly select a blinding scalar
            let blinding_scalar = util::random_scalar(rng);
            // modify the first elements of the vector
            w_vec_inverse[i] = w_vec_inverse[i] - blinding_scalar;
            // append last elements at the end of the vector
            w_vec_inverse.push(blinding_scalar);
        }

        Polynomial::from_coefficients_vec(w_vec_inverse)
    }

    /// Creates a [`Proof]` that demonstrates that a circuit is satisfied.
    ///
    /// # Note
    ///
    /// If you intend to construct multiple [`Proof`]s with different witnesses,
    /// after calling this method, the user should then call
    /// [`Prover::clear_witness`].
    /// This is automatically done when [`Prover::prove`] is called.
    pub fn prove_with_preprocessed<R: RngCore + CryptoRng>(
        &self,
        commit_key: &CommitKey,
        prover_key: &ProverKey,
        rng: &mut R,
    ) -> Result<Proof, Error> {
        let domain = EvaluationDomain::new(self.cs.gates())?;

        // Since the caller is passing a pre-processed circuit we assume that
        // the Transcript has been seeded with the preprocessed commitments
        let mut transcript = self.preprocessed_transcript.clone();

        // PIs have to be part of the transcript
        for pi in self.cs.to_dense_public_inputs().iter() {
            transcript.append_scalar(b"pi", pi);
        }

        // We fill with zeros up to the domain size, in order to match the
        // length of the vector used by the verifier in his side in the
        // implementation
        for _ in 0..(domain.size() - self.cs.to_dense_public_inputs().len()) {
            transcript.append_scalar(b"pi", &BlsScalar::from(0u64));
        }

        //** ROUND 1 **********************************************************
        // Convert wires to BlsScalars padding them to the correct domain size.
        // Note that `d_w` is added for the additional selector for 3-input
        // gates `q_4`.
        let pad = vec![BlsScalar::zero(); domain.size() - self.cs.a_w.len()];
        let a_w_scalar = &[&self.to_scalars(&self.cs.a_w)[..], &pad].concat();
        let b_w_scalar = &[&self.to_scalars(&self.cs.b_w)[..], &pad].concat();
        let c_w_scalar = &[&self.to_scalars(&self.cs.c_w)[..], &pad].concat();
        let d_w_scalar = &[&self.to_scalars(&self.cs.d_w)[..], &pad].concat();

        // Wires are now in evaluation form, convert them to coefficients so
        // that we may commit to them
        let a_w_poly = Prover::blind_poly(&a_w_scalar, 1, &domain, rng);
        let b_w_poly = Prover::blind_poly(&b_w_scalar, 1, &domain, rng);
        let c_w_poly = Prover::blind_poly(&c_w_scalar, 1, &domain, rng);
        let d_w_poly = Prover::blind_poly(&d_w_scalar, 1, &domain, rng);

        // Commit to wire polynomials
        // ([a(x)]_1, [b(x)]_1, [c(x)]_1, [d(x)]_1)
        let a_w_poly_commit = commit_key.commit(&a_w_poly)?;
        let b_w_poly_commit = commit_key.commit(&b_w_poly)?;
        let c_w_poly_commit = commit_key.commit(&c_w_poly)?;
        let d_w_poly_commit = commit_key.commit(&d_w_poly)?;

        // Add wire polynomial commitments to transcript
        transcript.append_commitment(b"a_w", &a_w_poly_commit);
        transcript.append_commitment(b"b_w", &b_w_poly_commit);
        transcript.append_commitment(b"c_w", &c_w_poly_commit);
        transcript.append_commitment(b"d_w", &d_w_poly_commit);

        //** ROUND 2 **********************************************************
        // Permutation challenges
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");

        let z_poly = Prover::blind_poly(
            &self.cs.perm.compute_permutation_vec(
                &domain,
                [a_w_scalar, b_w_scalar, c_w_scalar, d_w_scalar],
                &beta,
                &gamma,
                [
                    &prover_key.permutation.s_sigma_1.0,
                    &prover_key.permutation.s_sigma_2.0,
                    &prover_key.permutation.s_sigma_3.0,
                    &prover_key.permutation.s_sigma_4.0,
                ],
            ),
            2,
            &domain,
            rng,
        );

        // Commit to permutation polynomial
        let z_poly_commit = commit_key.commit(&z_poly)?;

        // Add commitment to permutation polynomial to transcript
        transcript.append_commitment(b"z", &z_poly_commit);

        //** ROUND 3 **********************************************************
        // Compute quotient challenge 'alpha'
        let alpha = transcript.challenge_scalar(b"alpha");
        let range_sep_challenge =
            transcript.challenge_scalar(b"range separation challenge");
        let logic_sep_challenge =
            transcript.challenge_scalar(b"logic separation challenge");
        let fixed_base_sep_challenge =
            transcript.challenge_scalar(b"fixed base separation challenge");
        let var_base_sep_challenge =
            transcript.challenge_scalar(b"variable base separation challenge");

        // Compute public inputs polynomial
        let pi_poly = Polynomial::from_coefficients_vec(
            domain.ifft(&self.cs.to_dense_public_inputs()),
        );

        // Compute quotient polynomial
        let t_poly = quotient_poly::compute(
            &domain,
            prover_key,
            &z_poly,
            (&a_w_poly, &b_w_poly, &c_w_poly, &d_w_poly),
            &pi_poly,
            &(
                alpha,
                beta,
                gamma,
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
            ),
        )?;

        // Split quotient polynomial into 4 degree `n` polynomials
        let (t_low_poly, t_mid_poly, t_high_poly, t_4_poly) =
            self.split_tx_poly(domain.size(), &t_poly);

        // Commit to split quotient polynomial
        let t_low_commit = commit_key.commit(&t_low_poly)?;
        let t_mid_commit = commit_key.commit(&t_mid_poly)?;
        let t_high_commit = commit_key.commit(&t_high_poly)?;
        let t_4_commit = commit_key.commit(&t_4_poly)?;

        // Add quotient polynomial commitments to transcript
        transcript.append_commitment(b"t_low", &t_low_commit);
        transcript.append_commitment(b"t_mid", &t_mid_commit);
        transcript.append_commitment(b"t_high", &t_high_commit);
        transcript.append_commitment(b"t_4", &t_4_commit);

        //** ROUND 4 **********************************************************
        // Compute evaluation challenge 'z'
        let z_challenge = transcript.challenge_scalar(b"z_challenge");
        // the evaluations are computed altogether in next round

        //** ROUND 5 **********************************************************
        // Compute linearization polynomial
        let (r_poly, evaluations) = linearization_poly::compute(
            &domain,
            prover_key,
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
            &c_w_poly,
            &d_w_poly,
            &t_poly,
            &z_poly,
        );

        // Add evaluations to transcript.
        // Part of these are from round 5 in the paper.
        // Note that even tough some of the evaluations are not added to the
        // transcript, they are still sent as part of the `Proof` in the return
        // value.
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

        // Compute Openings using KZG10
        // We merge the quotient polynomial using the challenge z so the SRS
        // is linear in the circuit size `n`
        let quot = Self::compute_quotient_opening_poly(
            domain.size(),
            &t_low_poly,
            &t_mid_poly,
            &t_high_poly,
            &t_4_poly,
            &z_challenge,
        );

        // Compute aggregate witness to polynomials evaluated at the evaluation
        // challenge z. The challenge v is selected inside
        let aggregate_witness = commit_key.compute_aggregate_witness(
            &[
                quot,
                r_poly,
                a_w_poly.clone(),
                b_w_poly.clone(),
                c_w_poly,
                d_w_poly.clone(),
                prover_key.permutation.s_sigma_1.0.clone(),
                prover_key.permutation.s_sigma_2.0.clone(),
                prover_key.permutation.s_sigma_3.0.clone(),
            ],
            &z_challenge,
            &mut transcript,
        );
        let w_z_chall_comm = commit_key.commit(&aggregate_witness)?;

        // Compute aggregate witness to polynomials evaluated at the shifted
        // evaluation challenge
        let shifted_aggregate_witness = commit_key.compute_aggregate_witness(
            &[z_poly, a_w_poly, b_w_poly, d_w_poly],
            &(z_challenge * domain.group_gen),
            &mut transcript,
        );
        let w_z_chall_w_comm = commit_key.commit(&shifted_aggregate_witness)?;

        // Create Proof
        Ok(Proof {
            a_comm: a_w_poly_commit,
            b_comm: b_w_poly_commit,
            c_comm: c_w_poly_commit,
            d_comm: d_w_poly_commit,

            z_comm: z_poly_commit,

            t_low_comm: t_low_commit,
            t_mid_comm: t_mid_commit,
            t_high_comm: t_high_commit,
            t_4_comm: t_4_commit,

            w_z_chall_comm,
            w_z_chall_w_comm,

            evaluations: evaluations.proof,
        })
    }

    /// Proves a circuit is satisfied, then clears the witness variables
    /// If the circuit is not pre-processed, then the preprocessed circuit will
    /// also be computed.
    pub fn prove<R: RngCore + CryptoRng>(
        &mut self,
        commit_key: &CommitKey,
        rng: &mut R,
    ) -> Result<Proof, Error> {
        let prover_key: &ProverKey;

        if self.prover_key.is_none() {
            // Preprocess circuit
            let prover_key = self.cs.preprocess_prover(
                commit_key,
                &mut self.preprocessed_transcript,
            )?;
            // Store preprocessed circuit and transcript in the Prover
            self.prover_key = Some(prover_key);
        }

        prover_key = self.prover_key.as_ref().unwrap();

        let proof =
            self.prove_with_preprocessed(commit_key, prover_key, rng)?;

        // Clear witness and reset composer variables
        self.clear_witness();

        Ok(proof)
    }
}
