use super::proof_system_errors::ProofErrors;
use crate::commitment_scheme::kzg10::CommitKey;
use crate::constraint_system::{StandardComposer, Variable};
use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::widget::ProverKey;
use crate::proof_system::{linearisation_poly, proof::Proof, quotient_poly};
use crate::transcript::TranscriptProtocol;
use anyhow::{Error, Result};
use dusk_bls12_381::Scalar;
use merlin::Transcript;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

/// Prover composes a circuit and builds a proof
#[allow(missing_debug_implementations)]
pub struct Prover {
    /// ProverKey which is used to create proofs about a specific PLONK circuit
    pub prover_key: Option<ProverKey>,

    pub(crate) cs: StandardComposer,
    /// Store the messages exchanged during the preprocessing stage
    /// This is copied each time, we make a proof
    pub preprocessed_transcript: Transcript,
}

impl Prover {
    /// Returns a mutable copy of the underlying composer
    pub fn mut_cs(&mut self) -> &mut StandardComposer {
        &mut self.cs
    }
    /// Preprocesses the underlying constraint system
    pub fn preprocess(&mut self, commit_key: &CommitKey) -> Result<(), Error> {
        if self.prover_key.is_some() {
            return Err(ProofErrors::CircuitAlreadyPreprocessed.into());
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
    /// Creates a new prover object
    pub fn new(label: &'static [u8]) -> Prover {
        Prover {
            prover_key: None,
            cs: StandardComposer::new(),
            preprocessed_transcript: Transcript::new(label),
        }
    }
    /// Returns the number of gates in the circuit
    pub fn circuit_size(&self) -> usize {
        self.cs.circuit_size()
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
    /// Computes the quotient opening polynomial.
    fn compute_quotient_opening_poly(
        n: usize,
        t_1_poly: &Polynomial,
        t_2_poly: &Polynomial,
        t_3_poly: &Polynomial,
        t_4_poly: &Polynomial,
        z_challenge: &Scalar,
    ) -> Polynomial {
        // Compute z^n , z^2n , z^3n
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
        let z_three_n = z_challenge.pow(&[3 * n as u64, 0, 0, 0]);

        let a = t_1_poly;
        let b = t_2_poly * &z_n;
        let c = t_3_poly * &z_two_n;
        let d = t_4_poly * &z_three_n;
        let abc = &(a + &b) + &c;
        &abc + &d
    }
    /// Convert variables to their actual witness values.
    pub(crate) fn to_scalars(&self, vars: &[Variable]) -> Vec<Scalar> {
        vars.par_iter().map(|var| self.cs.variables[var]).collect()
    }
    /// Resets the witnesses in the prover object.
    /// This function is used when the user wants to make multiple proofs with the same circuit.
    pub fn clear_witness(&mut self) {
        self.cs = StandardComposer::new();
    }

    /// Clears all data in the Prover
    /// This function is used when the user wants to use the same Prover to
    /// make a proof regarding a different circuit.
    pub fn clear(&mut self) {
        self.clear_witness();
        self.prover_key = None;
        self.preprocessed_transcript = Transcript::new(b"plonk");
    }

    /// Keys the transcript with additional seed information
    /// Wrapper around transcript.append_message
    pub fn key_transcript(&mut self, label: &'static [u8], message: &[u8]) {
        self.preprocessed_transcript.append_message(label, message);
    }

    /// Creates a Proof that a circuit is satisfied
    /// Note that if you intend to make multiple proofs, after calling this method, the user should then
    /// call `clear_witness`. This is automatically done when `prove` is called
    pub fn prove_with_preprocessed(
        &self,
        commit_key: &CommitKey,
        prover_key: &ProverKey,
    ) -> Result<Proof, Error> {
        let domain = EvaluationDomain::new(self.cs.circuit_size())?;

        // Since the caller is passing a pre-processed circuit
        // We assume that the Transcript has been seeded with the preprocessed
        // Commitments
        let mut transcript = self.preprocessed_transcript.clone();

        //1. Compute witness Polynomials
        //
        // Convert Variables to Scalars padding them to the
        // correct domain size.
        let pad = vec![Scalar::zero(); domain.size() - self.cs.w_l.len()];
        let w_l_scalar = &[&self.to_scalars(&self.cs.w_l)[..], &pad].concat();
        let w_r_scalar = &[&self.to_scalars(&self.cs.w_r)[..], &pad].concat();
        let w_o_scalar = &[&self.to_scalars(&self.cs.w_o)[..], &pad].concat();
        let w_4_scalar = &[&self.to_scalars(&self.cs.w_4)[..], &pad].concat();

        // Witnesses are now in evaluation form, convert them to coefficients
        // So that we may commit to them
        let w_l_poly = Polynomial::from_coefficients_vec(domain.ifft(w_l_scalar));
        let w_r_poly = Polynomial::from_coefficients_vec(domain.ifft(w_r_scalar));
        let w_o_poly = Polynomial::from_coefficients_vec(domain.ifft(w_o_scalar));
        let w_4_poly = Polynomial::from_coefficients_vec(domain.ifft(w_4_scalar));

        // Commit to witness polynomials
        let w_l_poly_commit = commit_key.commit(&w_l_poly)?;
        let w_r_poly_commit = commit_key.commit(&w_r_poly)?;
        let w_o_poly_commit = commit_key.commit(&w_o_poly)?;
        let w_4_poly_commit = commit_key.commit(&w_4_poly)?;

        // Add witness polynomial commitments to transcript
        transcript.append_commitment(b"w_l", &w_l_poly_commit);
        transcript.append_commitment(b"w_r", &w_r_poly_commit);
        transcript.append_commitment(b"w_o", &w_o_poly_commit);
        transcript.append_commitment(b"w_4", &w_4_poly_commit);

        // 2. Compute permutation polynomial
        //
        //
        // Compute permutation challenges; `beta` and `gamma`
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");

        let z_poly = self.cs.perm.compute_permutation_poly(
            &domain,
            &w_l_scalar,
            &w_r_scalar,
            &w_o_scalar,
            &w_4_scalar,
            &(beta, gamma),
            (
                &prover_key.permutation.left_sigma.0,
                &prover_key.permutation.right_sigma.0,
                &prover_key.permutation.out_sigma.0,
                &prover_key.permutation.fourth_sigma.0,
            ),
        );

        // Commit to permutation polynomial
        //
        let z_poly_commit = commit_key.commit(&z_poly)?;

        // Add permutation polynomial commitment to transcript
        transcript.append_commitment(b"z", &z_poly_commit);

        // 3. Compute public inputs polynomial
        let pi_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.cs.public_inputs));

        // 4. Compute quotient polynomial
        //
        // Compute quotient challenge; `alpha`
        let alpha = transcript.challenge_scalar(b"alpha");
        let range_sep_challenge = transcript.challenge_scalar(b"range separation challenge");
        let logic_sep_challenge = transcript.challenge_scalar(b"logic separation challenge");
        let fixed_base_sep_challenge =
            transcript.challenge_scalar(b"fixed base separation challenge");
        let var_base_sep_challenge =
            transcript.challenge_scalar(b"variable base separation challenge");

        let t_poly = quotient_poly::compute(
            &domain,
            &prover_key,
            &z_poly,
            (&w_l_poly, &w_r_poly, &w_o_poly, &w_4_poly),
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
        let (t_1_poly, t_2_poly, t_3_poly, t_4_poly) = self.split_tx_poly(domain.size(), &t_poly);

        // Commit to splitted quotient polynomial
        let t_1_commit = commit_key.commit(&t_1_poly)?;
        let t_2_commit = commit_key.commit(&t_2_poly)?;
        let t_3_commit = commit_key.commit(&t_3_poly)?;
        let t_4_commit = commit_key.commit(&t_4_poly)?;

        // Add quotient polynomial commitments to transcript
        transcript.append_commitment(b"t_1", &t_1_commit);
        transcript.append_commitment(b"t_2", &t_2_commit);
        transcript.append_commitment(b"t_3", &t_3_commit);
        transcript.append_commitment(b"t_4", &t_4_commit);

        // 4. Compute linearisation polynomial
        //
        // Compute evaluation challenge; `z`
        let z_challenge = transcript.challenge_scalar(b"z");

        let (lin_poly, evaluations) = linearisation_poly::compute(
            &domain,
            &prover_key,
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
            &w_l_poly,
            &w_r_poly,
            &w_o_poly,
            &w_4_poly,
            &t_poly,
            &z_poly,
        );

        // Add evaluations to transcript
        transcript.append_scalar(b"a_eval", &evaluations.proof.a_eval);
        transcript.append_scalar(b"b_eval", &evaluations.proof.b_eval);
        transcript.append_scalar(b"c_eval", &evaluations.proof.c_eval);
        transcript.append_scalar(b"d_eval", &evaluations.proof.d_eval);
        transcript.append_scalar(b"a_next_eval", &evaluations.proof.a_next_eval);
        transcript.append_scalar(b"b_next_eval", &evaluations.proof.b_next_eval);
        transcript.append_scalar(b"d_next_eval", &evaluations.proof.d_next_eval);
        transcript.append_scalar(b"left_sig_eval", &evaluations.proof.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &evaluations.proof.right_sigma_eval);
        transcript.append_scalar(b"out_sig_eval", &evaluations.proof.out_sigma_eval);
        transcript.append_scalar(b"q_arith_eval", &evaluations.proof.q_arith_eval);
        transcript.append_scalar(b"q_c_eval", &evaluations.proof.q_c_eval);
        transcript.append_scalar(b"q_l_eval", &evaluations.proof.q_l_eval);
        transcript.append_scalar(b"q_r_eval", &evaluations.proof.q_r_eval);
        transcript.append_scalar(b"perm_eval", &evaluations.proof.perm_eval);
        transcript.append_scalar(b"t_eval", &evaluations.quot_eval);
        transcript.append_scalar(b"r_eval", &evaluations.proof.lin_poly_eval);

        // 5. Compute Openings using KZG10
        //
        // We merge the quotient polynomial using the `z_challenge` so the SRS is linear in the circuit size `n`
        let quot = Self::compute_quotient_opening_poly(
            domain.size(),
            &t_1_poly,
            &t_2_poly,
            &t_3_poly,
            &t_4_poly,
            &z_challenge,
        );

        // Compute aggregate witness to polynomials evaluated at the evaluation challenge `z`
        let aggregate_witness = commit_key.compute_aggregate_witness(
            &[
                quot,
                lin_poly,
                w_l_poly.clone(),
                w_r_poly.clone(),
                w_o_poly,
                w_4_poly.clone(),
                prover_key.permutation.left_sigma.0.clone(),
                prover_key.permutation.right_sigma.0.clone(),
                prover_key.permutation.out_sigma.0.clone(),
            ],
            &z_challenge,
            &mut transcript,
        );
        let w_z_comm = commit_key.commit(&aggregate_witness)?;

        // Compute aggregate witness to polynomials evaluated at the shifted evaluation challenge
        let shifted_aggregate_witness = commit_key.compute_aggregate_witness(
            &[z_poly, w_l_poly, w_r_poly, w_4_poly],
            &(z_challenge * domain.group_gen),
            &mut transcript,
        );
        let w_zx_comm = commit_key.commit(&shifted_aggregate_witness)?;

        // Create Proof
        Ok(Proof {
            a_comm: w_l_poly_commit,
            b_comm: w_r_poly_commit,
            c_comm: w_o_poly_commit,
            d_comm: w_4_poly_commit,

            z_comm: z_poly_commit,

            t_1_comm: t_1_commit,
            t_2_comm: t_2_commit,
            t_3_comm: t_3_commit,
            t_4_comm: t_4_commit,

            w_z_comm,
            w_zw_comm: w_zx_comm,

            evaluations: evaluations.proof,
        })
    }

    /// Proves a circuit is satisfied, then clears the witness variables
    /// If the circuit is not pre-processed, then the preprocessed circuit will
    /// also be computed
    pub fn prove(&mut self, commit_key: &CommitKey) -> Result<Proof, Error> {
        let prover_key: &ProverKey;

        if self.prover_key.is_none() {
            // Preprocess circuit
            let prover_key = self
                .cs
                .preprocess_prover(commit_key, &mut self.preprocessed_transcript)?;
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
