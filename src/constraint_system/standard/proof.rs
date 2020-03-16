use super::linearisation_poly::ProofEvaluations;
use super::PreProcessedCircuit;
use crate::commitment_scheme::kzg10::{AggregateProof, Proof as SingleProof};
use crate::commitment_scheme::kzg10::{Commitment, VerifierKey};
use crate::fft::{EvaluationDomain, Polynomial};
use crate::permutation::constants::{K1, K2};
use crate::transcript::TranscriptProtocol;
use bls12_381::{multiscalar_mul::pippenger, pairing, G1Affine, G1Projective, Scalar};
pub struct Proof {
    // Commitment to the witness polynomial for the left wires
    pub a_comm: Commitment,
    // Commitment to the witness polynomial for the right wires
    pub b_comm: Commitment,
    // Commitment to the witness polynomial for the output wires
    pub c_comm: Commitment,

    // Commitment to the permutation polynomial
    pub z_comm: Commitment,

    // Commitment to the quotient polynomial
    pub t_lo_comm: Commitment,
    pub t_mid_comm: Commitment,
    pub t_hi_comm: Commitment,

    // Commitment to the opening polynomial
    pub w_z_comm: Commitment,
    // Commitment to the shifted opening polynomial
    pub w_zw_comm: Commitment,

    pub evaluations: ProofEvaluations,
}

impl Proof {
    pub fn empty() -> Proof {
        Proof {
            a_comm: Commitment::empty(),
            b_comm: Commitment::empty(),
            c_comm: Commitment::empty(),

            z_comm: Commitment::empty(),

            t_lo_comm: Commitment::empty(),
            t_mid_comm: Commitment::empty(),
            t_hi_comm: Commitment::empty(),

            w_z_comm: Commitment::empty(),
            w_zw_comm: Commitment::empty(),
            evaluations: ProofEvaluations {
                a_eval: Scalar::zero(),
                b_eval: Scalar::zero(),
                c_eval: Scalar::zero(),

                left_sigma_eval: Scalar::zero(),
                right_sigma_eval: Scalar::zero(),

                lin_poly_eval: Scalar::zero(),

                perm_eval: Scalar::zero(),
            },
        }
    }

    // Includes the commitments to the witness polynomials for left
    // right and output wires in the proof
    pub fn set_witness_poly_commitments(
        &mut self,
        a_comm: &Commitment,
        b_comm: &Commitment,
        c_comm: &Commitment,
    ) -> () {
        self.a_comm = *a_comm;
        self.b_comm = *b_comm;
        self.c_comm = *c_comm;
    }

    pub fn verify(
        &self,
        preprocessed_circuit: &PreProcessedCircuit,
        transcript: &mut dyn TranscriptProtocol,
        verifier_key: &VerifierKey,
        pub_inputs: &[Scalar],
    ) -> bool {
        let domain = EvaluationDomain::new(preprocessed_circuit.n).unwrap();

        // XXX: Check if components are valid

        // In order for the Verifier and Prover to have the same view in the non-interactive setting
        // Both parties must commit the same elements into the transcript
        // Below the verifier will simulate an interaction with the prover by adding the same elements
        // that the prover added into the transcript, hence generating the same challenges
        //
        // Add commitment to witness polynomials to transcript
        transcript.append_commitment(b"w_l", &self.a_comm);
        transcript.append_commitment(b"w_r", &self.b_comm);
        transcript.append_commitment(b"w_o", &self.c_comm);

        // Compute beta and gamma challenges
        let beta = transcript.challenge_scalar(b"beta");
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");

        // Add commitment to permutation polynomial to transcript
        transcript.append_commitment(b"z", &self.z_comm);

        // Compute quotient challenge
        let alpha = transcript.challenge_scalar(b"alpha");

        // Add commitment to quotient polynomial to transcript
        transcript.append_commitment(b"t_lo", &self.t_lo_comm);
        transcript.append_commitment(b"t_mid", &self.t_mid_comm);
        transcript.append_commitment(b"t_hi", &self.t_hi_comm);

        // Compute evaluation challenge
        let z_challenge = transcript.challenge_scalar(b"z");

        // Compute first lagrange polynomial evaluated at `z_challenge`
        let l1_eval = domain.evaluate_all_lagrange_coefficients(&z_challenge)[0];

        // Compute quotient polynomial evaluated at `z_challenge`
        let t_eval = self.compute_quotient_evaluation(
            &domain,
            pub_inputs,
            &alpha,
            &beta,
            &gamma,
            &z_challenge,
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
        transcript.append_scalar(b"left_sig_eval", &self.evaluations.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &self.evaluations.right_sigma_eval);
        transcript.append_scalar(b"perm_eval", &self.evaluations.perm_eval);
        transcript.append_scalar(b"t_eval", &t_eval);
        transcript.append_scalar(b"r_eval", &self.evaluations.lin_poly_eval);

        // Compute linearisation commitment
        let r_comm = self.compute_linearisation_commitment(
            &alpha,
            &beta,
            &gamma,
            &z_challenge,
            &l1_eval,
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
        aggregate_proof.add_part((
            self.evaluations.left_sigma_eval,
            *preprocessed_circuit.left_sigma_comm(),
        ));
        aggregate_proof.add_part((
            self.evaluations.right_sigma_eval,
            *preprocessed_circuit.right_sigma_comm(),
        ));
        // Flatten proof with opening challenge
        let flattened_proof = aggregate_proof.flatten(transcript);

        // Add commitment to openings to transcript
        transcript.append_commitment(b"w_z", &self.w_z_comm);
        transcript.append_commitment(b"w_z_w", &self.w_zw_comm);

        // Compose the Single Proof
        let single_proof = SingleProof {
            commitment_to_witness: self.w_zw_comm,
            evaluated_point: self.evaluations.perm_eval,
            commitment_to_polynomial: self.z_comm,
        };

        // Batch check
        verifier_key.batch_check(
            &[z_challenge, (z_challenge * domain.group_gen)],
            &[flattened_proof, single_proof],
            transcript,
        )
    }

    fn compute_quotient_evaluation(
        &self,
        domain: &EvaluationDomain,
        pub_inputs: &[Scalar],
        alpha: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
        z_challenge: &Scalar,
        l1_eval: &Scalar,
        z_hat_eval: &Scalar,
    ) -> Scalar {
        // Compute zero polynomial evaluated at `z_challenge`
        let z_h_eval = domain.evaluate_vanishing_polynomial(z_challenge);

        // Compute the public input polynomial evaluated at `z_challenge`
        let pi_poly = Polynomial::from_coefficients_vec(domain.ifft(&pub_inputs));
        let pi_eval = pi_poly.evaluate(&z_challenge);

        let alpha_sq = alpha.square();
        let alpha_cu = alpha_sq * alpha;

        // r + PI(z) * alpha
        let a = self.evaluations.lin_poly_eval + (pi_eval * alpha);

        // a + beta * sigma_1 + gamma
        let beta_sig1 = beta * self.evaluations.left_sigma_eval;
        let b_0 = self.evaluations.a_eval + beta_sig1 + gamma;

        // b+ beta * sigma_2 + gamma
        let beta_sig2 = beta * self.evaluations.right_sigma_eval;
        let b_1 = self.evaluations.b_eval + beta_sig2 + gamma;

        // ((c + gamma) * z_hat) * alpha^2
        let b_2 = (self.evaluations.c_eval + gamma) * z_hat_eval * alpha_sq;

        let b = b_0 * b_1 * b_2;

        // l_1(z) * alpha^3
        let c = l1_eval * alpha_cu;

        let t_eval = (a - b - c) * z_h_eval.invert().unwrap();

        t_eval
    }

    fn compute_quotient_commitment(&self, z_challenge: &Scalar, n: usize) -> Commitment {
        let z_n = z_challenge.pow(&[n as u64, 0, 0, 0]);
        let z_two_n = z_challenge.pow(&[2 * n as u64, 0, 0, 0]);
        let t_comm = self.t_lo_comm.0 + self.t_mid_comm.0 * z_n + self.t_hi_comm.0 * z_two_n;
        Commitment::from_projective(t_comm)
    }

    fn compute_linearisation_commitment(
        &self,
        alpha: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
        z_challenge: &Scalar,
        l1_eval: &Scalar,
        preprocessed_circuit: &PreProcessedCircuit,
    ) -> Commitment {
        let mut scalars: Vec<_> = Vec::with_capacity(6);
        let mut points: Vec<G1Affine> = Vec::with_capacity(6);

        let alpha_sq = alpha * alpha;
        let alpha_cu = alpha_sq * alpha;

        scalars.push(self.evaluations.a_eval * self.evaluations.b_eval * alpha);
        points.push(preprocessed_circuit.qm_comm().0);

        scalars.push(self.evaluations.a_eval * alpha);
        points.push(preprocessed_circuit.ql_comm().0);

        scalars.push(self.evaluations.b_eval * alpha);
        points.push(preprocessed_circuit.qr_comm().0);

        scalars.push(self.evaluations.c_eval * alpha);
        points.push(preprocessed_circuit.qo_comm().0);

        scalars.push(*alpha);
        points.push(preprocessed_circuit.qc_comm().0);

        // (a_eval + beta * z + gamma)(b_eval + beta * z * k1 + gamma)(c_eval + beta * k2* z + gamma) * alpha^2
        let x = {
            let beta_z = beta * z_challenge;
            let q_0 = self.evaluations.a_eval + beta_z + gamma;

            let beta_k1_z = beta * K1 * z_challenge;
            let q_1 = self.evaluations.b_eval + beta_k1_z + gamma;

            let beta_k2_z = beta * K2 * z_challenge;
            let q_2 = (self.evaluations.c_eval + beta_k2_z + gamma) * alpha_sq;

            q_0 * q_1 * q_2
        };

        // l1(z) * alpha^3
        let r = l1_eval * alpha_cu;

        scalars.push(x + r);
        points.push(self.z_comm.0);

        // -(a_eval + beta * sigma_1_eval + gamma)(b_eval + beta * sigma_2_eval + gamma)(c_eval + beta * sigma_3_eval + gamma) *alpha^2
        let y = {
            let beta_sigma_1 = beta * self.evaluations.left_sigma_eval;
            let q_0 = self.evaluations.a_eval + beta_sigma_1 + gamma;

            let beta_sigma_2 = beta * &self.evaluations.right_sigma_eval;
            let q_1 = self.evaluations.b_eval + beta_sigma_2 + gamma;

            let q_2 = beta * self.evaluations.perm_eval * alpha * alpha;

            -(q_0 * q_1 * q_2)
        };
        scalars.push(y);
        points.push(preprocessed_circuit.out_sigma_comm().0);

        Commitment::from_projective(pippenger(
            points.iter().map(|P| G1Projective::from(P)),
            scalars.into_iter(),
        ))
    }
}
