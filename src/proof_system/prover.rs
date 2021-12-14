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
    plonkup::MultiSet,
    proof_system::{
        linearization_poly, proof::Proof, quotient_poly, ProverKey,
    },
    transcript::TranscriptProtocol,
};
use alloc::vec::Vec;
use dusk_bls12_381::BlsScalar;
use merlin::Transcript;

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
        q_low_poly: &Polynomial,
        q_mid_poly: &Polynomial,
        q_high_poly: &Polynomial,
        q_4_poly: &Polynomial,
        z_challenge: &BlsScalar,
    ) -> Polynomial {
        // Compute z^n , z^2n , z^3n
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
        let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);

        let a = q_low_poly;
        let b = q_mid_poly * &z_n;
        let c = q_high_poly * &z_two_n;
        let d = q_4_poly * &z_three_n;
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
    /// if hiding degree = 1: (b2*X(n+1) + b1*X^n - b2*X - b1) + w_vec
    /// if hiding degree = 2: (b3*X^(n+2) + b2*X(n+1) + b1*X^n - b3*X^2 - b2*X
    /// - b1) + w_vec
    pub(crate) fn blind_poly(
        w_vec: &Vec<dusk_bls12_381::BlsScalar>,
        hiding_degree: usize,
        domain: &EvaluationDomain,
    ) -> Polynomial {
        let mut w_vec_i = domain.ifft(w_vec);

        for i in 0..hiding_degree + 1 {
            // we declare and randomly select a blinding scalar
            // TODO: implement randomness
            //let blinding_scalar = util::random_scalar(&mut rand_core::OsRng);
            let blinding_scalar = BlsScalar::from(1234); // TO BE RANDOM!
            w_vec_i[i] = w_vec_i[i] - blinding_scalar; // modify the first elements of the vector
            w_vec_i.push(blinding_scalar); // append last elements at the end of
                                           // the vector
        }

        Polynomial::from_coefficients_vec(w_vec_i)
    }

    /// Creates a [`Proof]` that demonstrates that a circuit is satisfied.
    ///
    /// # Note
    ///
    /// If you intend to construct multiple [`Proof`]s with different witnesses,
    /// after calling this method, the user should then call
    /// [`Prover::clear_witness`].
    /// This is automatically done when [`Prover::prove`] is called.
    pub fn prove_with_preprocessed(
        &self,
        commit_key: &CommitKey,
        prover_key: &ProverKey,
    ) -> Result<Proof, Error> {
        // make sure the domain is big enough to handle the circuit as well as
        // the lookup table
        let domain = EvaluationDomain::new(core::cmp::max(
            self.cs.gates(),
            self.cs.lookup_table.0.len(),
        ))?;

        // Since the caller is passing a pre-processed circuit we assume that
        // the Transcript has been seeded with the preprocessed commitments
        let mut transcript = self.preprocessed_transcript.clone();

        //** ROUND 1 **********************************************************
        // Convert wires to BlsScalars padding them to the correct domain size.
        // Note that `d_w` is added for the additional selector for 3-input
        // gates `q_4`.
        let pad = vec![BlsScalar::zero(); domain.size() - self.cs.a_w.len()];
        let a_w_scalar = &[&self.to_scalars(&self.cs.a_w)[..], &pad].concat();
        let b_w_scalar = &[&self.to_scalars(&self.cs.b_w)[..], &pad].concat();
        let c_w_scalar = &[&self.to_scalars(&self.cs.c_w)[..], &pad].concat();
        let d_w_scalar = &[&self.to_scalars(&self.cs.d_w)[..], &pad].concat();

        // Make sure q_k is also the right size for constructing f
        let padded_q_k = [&self.cs.q_k[..], &pad].concat();

        // Wires are now in evaluation form, convert them to coefficients so
        // that we may commit to them
        let a_w_poly = Prover::blind_poly(&a_w_scalar, 1, &domain);
        let b_w_poly = Prover::blind_poly(&b_w_scalar, 1, &domain);
        let c_w_poly = Prover::blind_poly(&c_w_scalar, 1, &domain);
        let d_w_poly = Prover::blind_poly(&d_w_scalar, 1, &domain);

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
        // Generate table compression factor
        let zeta = transcript.challenge_scalar(b"zeta");

        // Compress table into vector of single elements
        let compressed_t_multiset = MultiSet::compress_four_arity(
            [
                &prover_key.lookup.table_1.0,
                &prover_key.lookup.table_2.0,
                &prover_key.lookup.table_3.0,
                &prover_key.lookup.table_4.0,
            ],
            zeta,
        );

        // Compute t'
        let t_prime_poly = Polynomial::from_coefficients_vec(
            domain.ifft(&compressed_t_multiset.0),
        );

        // Compute table f
        // When q_k[i] is zero the wire value is replaced with a dummy
        // value Currently set as the first row of the public table
        // If q_k is one the wire values are preserved
        let f_1_scalar = a_w_scalar
            .iter()
            .zip(&padded_q_k)
            .map(|(w, s)| {
                w * s + (BlsScalar::one() - s) * compressed_t_multiset.0[0]
            })
            .collect::<Vec<BlsScalar>>();
        let f_2_scalar = b_w_scalar
            .iter()
            .zip(&padded_q_k)
            .map(|(w, s)| w * s)
            .collect::<Vec<BlsScalar>>();
        let f_3_scalar = c_w_scalar
            .iter()
            .zip(&padded_q_k)
            .map(|(w, s)| w * s)
            .collect::<Vec<BlsScalar>>();
        let f_4_scalar = d_w_scalar
            .iter()
            .zip(&padded_q_k)
            .map(|(w, s)| w * s)
            .collect::<Vec<BlsScalar>>();

        // Compress all wires into a single vector
        let compressed_f_multiset = MultiSet::compress_four_arity(
            [
                &MultiSet::from(&f_1_scalar[..]),
                &MultiSet::from(&f_2_scalar[..]),
                &MultiSet::from(&f_3_scalar[..]),
                &MultiSet::from(&f_4_scalar[..]),
            ],
            zeta,
        );

        // Compute long query poly
        let f_poly = Prover::blind_poly(&compressed_f_multiset.0, 1, &domain);

        // Commit to query polynomial
        let f_poly_commit = commit_key.commit(&f_poly)?;

        // Add f_poly commitment to transcript
        transcript.append_commitment(b"f", &f_poly_commit);

        // Compute s, as the sorted and concatenated version of f and t
        let s = compressed_t_multiset
            .sorted_concat(&compressed_f_multiset)
            .unwrap();

        // Compute first and second halves of s, as h_1 and h_2
        let (h_1, h_2) = s.halve_alternating();

        // Compute h polys
        let h_1_poly = Prover::blind_poly(&h_1.0, 2, &domain);
        let h_2_poly = Prover::blind_poly(&h_2.0, 1, &domain);

        // Commit to h polys
        let h_1_poly_commit = commit_key.commit(&h_1_poly).unwrap();
        let h_2_poly_commit = commit_key.commit(&h_2_poly).unwrap();

        // Add h polynomials to transcript
        transcript.append_commitment(b"h1", &h_1_poly_commit);
        transcript.append_commitment(b"h2", &h_2_poly_commit);

        //** ROUND 3 **********************************************************
        // Permutation challenges
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");
        let delta = transcript.challenge_scalar(b"delta");
        let epsilon = transcript.challenge_scalar(b"epsilon");

        let z_1_poly = Prover::blind_poly(
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
        );

        // Commit to permutation polynomial
        let z_1_poly_commit = commit_key.commit(&z_1_poly)?;

        // Add commitment to permutation polynomial to transcript
        transcript.append_commitment(b"z_1", &z_1_poly_commit);

        // Compute lookup permutation poly
        let z_2_poly = Prover::blind_poly(
            &self.cs.perm.compute_lookup_permutation_vec(
                &domain,
                &compressed_f_multiset.0,
                &compressed_t_multiset.0,
                &h_1.0,
                &h_2.0,
                &delta,
                &epsilon,
            ),
            2,
            &domain,
        );

        // Commit to permutation polynomial
        let z_2_poly_commit = commit_key.commit(&z_2_poly)?;

        // Add permutation polynomial commitment to transcript
        transcript.append_commitment(b"z_2", &z_2_poly_commit);

        //** ROUND 4 **********************************************************
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
        let lookup_sep_challenge =
            transcript.challenge_scalar(b"lookup challenge");

        // Compute public inputs polynomial
        let pi_poly = Polynomial::from_coefficients_vec(
            domain.ifft(&self.cs.to_dense_public_inputs()),
        );

        // Compute quotient polynomial
        let q_poly = quotient_poly::compute(
            &domain,
            prover_key,
            &z_1_poly,
            &z_2_poly,
            (&a_w_poly, &b_w_poly, &c_w_poly, &d_w_poly),
            &f_poly,
            &t_prime_poly,
            &h_1_poly,
            &h_2_poly,
            &pi_poly,
            &(
                alpha,
                beta,
                gamma,
                delta,
                epsilon,
                zeta,
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
                lookup_sep_challenge,
            ),
        )?;

        // Split quotient polynomial into 4 degree `n` polynomials
        let (q_low_poly, q_mid_poly, q_high_poly, q_4_poly) =
            self.split_tx_poly(domain.size(), &q_poly);

        // Commit to split quotient polynomial
        let q_low_commit = commit_key.commit(&q_low_poly)?;
        let q_mid_commit = commit_key.commit(&q_mid_poly)?;
        let q_high_commit = commit_key.commit(&q_high_poly)?;
        let q_4_commit = commit_key.commit(&q_4_poly)?;

        // Add quotient polynomial commitments to transcript
        transcript.append_commitment(b"q_low", &q_low_commit);
        transcript.append_commitment(b"q_mid", &q_mid_commit);
        transcript.append_commitment(b"q_high", &q_high_commit);
        transcript.append_commitment(b"q_4", &q_4_commit);

        //** ROUND 5 **********************************************************
        // Compute evaluation challenge 'z'
        let z_challenge = transcript.challenge_scalar(b"z_challenge");
        // the evaluations are computed altogether in next round

        //** ROUND 6 **********************************************************
        // Compute linearization polynomial
        // We compute also `f_eval`, `t_eval`, `t_prime_eval` and
        // `t_prime_next_eval` when creating the linearization poly.
        let (r_poly, evaluations) = linearization_poly::compute(
            &domain,
            prover_key,
            &(
                alpha,
                beta,
                gamma,
                delta,
                epsilon,
                zeta,
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
                lookup_sep_challenge,
                z_challenge,
            ),
            &a_w_poly,
            &b_w_poly,
            &c_w_poly,
            &d_w_poly,
            &q_poly,
            &z_1_poly,
            &f_poly,
            &h_1_poly,
            &h_2_poly,
            &t_prime_poly,
            &z_2_poly,
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
        transcript.append_scalar(b"q_k_eval", &evaluations.proof.q_k_eval);
        transcript.append_scalar(b"perm_eval", &evaluations.proof.perm_eval);
        transcript.append_scalar(
            b"lookup_perm_eval",
            &evaluations.proof.lookup_perm_eval,
        );
        transcript.append_scalar(b"h_1_eval", &evaluations.proof.h_1_eval);
        transcript
            .append_scalar(b"h_1_next_eval", &evaluations.proof.h_1_next_eval);
        transcript.append_scalar(b"h_2_eval", &evaluations.proof.h_2_eval);
        transcript.append_scalar(b"t_eval", &evaluations.t_eval);
        transcript.append_scalar(b"r_eval", &evaluations.proof.r_poly_eval);

        // Compute Openings using KZG10
        // We merge the quotient polynomial using the challenge z so the SRS
        // is linear in the circuit size `n`
        let quot = Self::compute_quotient_opening_poly(
            domain.size(),
            &q_low_poly,
            &q_mid_poly,
            &q_high_poly,
            &q_4_poly,
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
                f_poly,
                h_1_poly.clone(),
                h_2_poly,
                t_prime_poly.clone(),
            ],
            &z_challenge,
            &mut transcript,
        );
        let w_z_chall_comm = commit_key.commit(&aggregate_witness)?;

        // Compute aggregate witness to polynomials evaluated at the shifted
        // evaluation challenge
        let shifted_aggregate_witness = commit_key.compute_aggregate_witness(
            &[
                z_1_poly,
                a_w_poly,
                b_w_poly,
                d_w_poly,
                h_1_poly,
                z_2_poly,
                t_prime_poly,
            ],
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

            f_comm: f_poly_commit,

            h_1_comm: h_1_poly_commit,
            h_2_comm: h_2_poly_commit,

            z_1_comm: z_1_poly_commit,
            z_2_comm: z_2_poly_commit,

            q_low_comm: q_low_commit,
            q_mid_comm: q_mid_commit,
            q_high_comm: q_high_commit,
            q_4_comm: q_4_commit,

            w_z_chall_comm,
            w_z_chall_w_comm,

            evaluations: evaluations.proof,
        })
    }

    /// Proves a circuit is satisfied, then clears the witness variables
    /// If the circuit is not pre-processed, then the preprocessed circuit will
    /// also be computed.
    pub fn prove(&mut self, commit_key: &CommitKey) -> Result<Proof, Error> {
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

        let proof = self.prove_with_preprocessed(commit_key, prover_key)?;

        // Clear witness and reset composer variables
        self.clear_witness();

        Ok(proof)
    }
}
