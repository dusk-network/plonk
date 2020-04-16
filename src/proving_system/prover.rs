use crate::commitment_scheme::kzg10::ProverKey;
use crate::constraint_system::{StandardComposer, Variable};
use crate::fft::{EvaluationDomain, Polynomial};
use crate::proving_system::linearisation_poly;
use crate::proving_system::quotient_poly;
use crate::proving_system::{proof::Proof, PreProcessedCircuit};
use crate::transcript::TranscriptProtocol;
use bls12_381::Scalar;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

/// Prover
pub struct Prover {
    cs: StandardComposer,

    w_l: Vec<Variable>,
    w_r: Vec<Variable>,
    w_o: Vec<Variable>,
    w_4: Vec<Variable>,

    public_inputs: Vec<Scalar>,
}

impl Prover {
    /// Split `t(X)` poly into 3 degree `n` polynomials.
    pub fn split_tx_poly(
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
    // Prove will compute the pre-processed polynomials and
    // produce a proof
    fn prove(
        &mut self,
        commit_key: &ProverKey,
        preprocessed_circuit: &PreProcessedCircuit,
        transcript: &mut dyn TranscriptProtocol,
    ) -> Proof {
        let domain = EvaluationDomain::new(self.cs.circuit_size()).unwrap();

        //1. Compute witness Polynomials
        //
        // Convert Variables to Scalars
        // XXX: Maybe there's no need to allocate `to_scalars` returning &[Scalar].
        let w_l_scalar = self.to_scalars(&self.w_l);
        let w_r_scalar = self.to_scalars(&self.w_r);
        let w_o_scalar = self.to_scalars(&self.w_o);
        let w_4_scalar = self.to_scalars(&self.w_4);

        // Witnesses are now in evaluation form, convert them to coefficients
        // So that we may commit to them
        let w_l_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_l_scalar));
        let w_r_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_r_scalar));
        let w_o_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_o_scalar));
        let w_4_poly = Polynomial::from_coefficients_vec(domain.ifft(&w_4_scalar));

        // Commit to witness polynomials
        let w_l_poly_commit = commit_key.commit(&w_l_poly).unwrap();
        let w_r_poly_commit = commit_key.commit(&w_r_poly).unwrap();
        let w_o_poly_commit = commit_key.commit(&w_o_poly).unwrap();
        let w_4_poly_commit = commit_key.commit(&w_4_poly).unwrap();

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
                &preprocessed_circuit.permutation.left_sigma.polynomial,
                &preprocessed_circuit.permutation.right_sigma.polynomial,
                &preprocessed_circuit.permutation.out_sigma.polynomial,
                &preprocessed_circuit.permutation.fourth_sigma.polynomial,
            ),
        );

        // Commit to permutation polynomial
        //
        let z_poly_commit = commit_key.commit(&z_poly).unwrap();

        // Add permutation polynomial commitment to transcript
        transcript.append_commitment(b"z", &z_poly_commit);

        // 3. Compute public inputs polynomial
        let pi_poly = Polynomial::from_coefficients_vec(domain.ifft(&self.public_inputs));

        // 4. Compute quotient polynomial
        //
        // Compute quotient challenge; `alpha`
        let alpha = transcript.challenge_scalar(b"alpha");

        let t_poly = quotient_poly::compute(
            &domain,
            &preprocessed_circuit,
            &z_poly,
            (&w_l_poly, &w_r_poly, &w_o_poly, &w_4_poly),
            &pi_poly,
            &(alpha, beta, gamma),
        );

        // Split quotient polynomial into 4 degree `n` polynomials
        let (t_1_poly, t_2_poly, t_3_poly, t_4_poly) = self.split_tx_poly(domain.size(), &t_poly);

        // Commit to splitted quotient polynomial
        let t_1_commit = commit_key.commit(&t_1_poly).unwrap();
        let t_2_commit = commit_key.commit(&t_2_poly).unwrap();
        let t_3_commit = commit_key.commit(&t_3_poly).unwrap();
        let t_4_commit = commit_key.commit(&t_4_poly).unwrap();

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
            &preprocessed_circuit,
            &(alpha, beta, gamma, z_challenge),
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
                preprocessed_circuit
                    .permutation
                    .left_sigma
                    .polynomial
                    .clone(),
                preprocessed_circuit
                    .permutation
                    .right_sigma
                    .polynomial
                    .clone(),
                preprocessed_circuit
                    .permutation
                    .out_sigma
                    .polynomial
                    .clone(),
            ],
            &z_challenge,
            transcript,
        );
        let w_z_comm = commit_key.commit(&aggregate_witness).unwrap();

        // Compute aggregate witness to polynomials evaluated at the shifted evaluation challenge
        let shifted_aggregate_witness = commit_key.compute_aggregate_witness(
            &[z_poly, w_l_poly, w_r_poly, w_4_poly],
            &(z_challenge * domain.group_gen),
            transcript,
        );
        let w_zx_comm = commit_key.commit(&shifted_aggregate_witness).unwrap();

        // Create Proof
        Proof {
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
        }
    }
}
