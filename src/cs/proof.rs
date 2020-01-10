use super::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::curves::PairingEngine;
use algebra::{
    curves::{AffineCurve, ProjectiveCurve},
    fields::{Field, PrimeField},
    groups::Group,
    msm::VariableBaseMSM,
};
use ff_fft::EvaluationDomain;
use poly_commit::kzg10::{Commitment, VerifierKey};
pub struct Proof<E: PairingEngine> {
    // Commitment to the witness polynomial for the left wires
    pub a_comm: Commitment<E>,
    // Commitment to the witness polynomial for the right wires
    pub b_comm: Commitment<E>,
    // Commitment to the witness polynomial for the output wires
    pub c_comm: Commitment<E>,

    // Commitment to the permutation polynomial
    pub z_comm: Commitment<E>,

    // Commitment to the quotient polynomial
    pub t_lo_comm: Commitment<E>,
    pub t_mid_comm: Commitment<E>,
    pub t_hi_comm: Commitment<E>,

    // Commitment to the opening polynomial
    pub w_z_comm: Commitment<E>,
    // Commitment to the shifted opening polynomial
    pub w_zw_comm: Commitment<E>,

    // Evaluation of the witness polynomial for the left wires at `z`
    pub a_eval: E::Fr,
    // Evaluation of the witness polynomial for the right wires at `z`
    pub b_eval: E::Fr,
    // Evaluation of the witness polynomial for the output wires at `z`
    pub c_eval: E::Fr,

    // Evaluation of the left sigma polynomial at `z`
    pub left_sigma_eval: E::Fr,
    // Evaluation of the right sigma polynomial at `z`
    pub right_sigma_eval: E::Fr,

    // Evaluation of the linearisation sigma polynomial at `z`
    pub lin_poly_eval: E::Fr,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of unity`
    pub z_hat_eval: E::Fr,
    // XXX: Need to confirm that for custom gates we do need more commitments for custom selector polynomial, as the selector polynomial is a part of the circit description
    // Furthermore, we may not need any extra commitments as the checks are baked into the quotient polynomial and the setup elements can be put into the witness polynomials

    // XXX:DEBUG VALUES (DELETE ONCE VERIFIER PASSES)
    pub debug_t_eval: E::Fr,
    pub debug_z: E::Fr,
    pub debug_alpha: E::Fr,
    pub debug_gamma: E::Fr,
    pub debug_beta: E::Fr,
}

impl<E: PairingEngine> Proof<E> {
    pub fn empty() -> Proof<E> {
        use algebra::fields::Field;
        use poly_commit::data_structures::PCCommitment;
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

            a_eval: E::Fr::zero(),
            b_eval: E::Fr::zero(),
            c_eval: E::Fr::zero(),

            left_sigma_eval: E::Fr::zero(),
            right_sigma_eval: E::Fr::zero(),

            lin_poly_eval: E::Fr::zero(),

            z_hat_eval: E::Fr::zero(),

            // DEBUG VALUES, DELETE ONCE VERIFIER PASSES
            debug_t_eval: E::Fr::zero(),
            debug_z: E::Fr::zero(),
            debug_alpha: E::Fr::zero(),
            debug_beta: E::Fr::zero(),
            debug_gamma: E::Fr::zero(),
        }
    }

    pub fn verify(
        &self,
        preprocessed_circuit: &PreProcessedCircuit<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        verifier_key: &VerifierKey<E>,
    ) -> bool {
        let domain = EvaluationDomain::new(preprocessed_circuit.n).unwrap();

        // XXX: Check if components are valid

        // Add witness polynomials to transcript
        transcript.append_commitment(b"w_l", &self.a_comm);
        transcript.append_commitment(b"w_r", &self.b_comm);
        transcript.append_commitment(b"w_o", &self.c_comm);

        // Compute beta and gamma
        let beta = transcript.challenge_scalar(b"beta");
        assert_eq!(beta, self.debug_beta);
        transcript.append_scalar(b"beta", &beta);
        let gamma = transcript.challenge_scalar(b"gamma");
        assert_eq!(gamma, self.debug_gamma);
        // Add commitment to permutation polynomial to transcript
        transcript.append_commitment(b"z", &self.z_comm);
        // Compute quotient challenge
        let alpha = transcript.challenge_scalar(b"alpha");
        assert_eq!(self.debug_alpha, alpha);
        // Add commitment to quotient polynomial to transcript
        transcript.append_commitment(b"t_lo", &self.t_lo_comm);
        transcript.append_commitment(b"t_mid", &self.t_mid_comm);
        transcript.append_commitment(b"t_hi", &self.t_hi_comm);
        // Compute evaluation challenge
        let z_challenge = transcript.challenge_scalar(b"z");
        assert_eq!(z_challenge, self.debug_z);
        // Compute zero polynomial evaluated at `z_challenge`
        let z_h_eval = domain.evaluate_vanishing_polynomial(z_challenge);

        // Compute first lagrange polynomial evaluated at `z_challenge`
        let l1_eval = domain.evaluate_all_lagrange_coefficients(z_challenge)[0];

        // XXX: Compute the public input polynomial evaluated at `z_challenge`
        // Currently no API to accept public input
        let pi_eval = E::Fr::zero();

        // Compute quotient polynomial evaluated at `z_challenge`
        let t_eval = self.compute_quotient_evaluation(
            pi_eval,
            alpha,
            beta,
            gamma,
            l1_eval,
            z_h_eval,
            self.z_hat_eval,
        );
        // DEBUG statement remove once verification passes
        assert_eq!(self.debug_t_eval, t_eval);

        // Add evaluations to transcript
        transcript.append_scalar(b"a_eval", &self.a_eval);
        transcript.append_scalar(b"b_eval", &self.b_eval);
        transcript.append_scalar(b"c_eval", &self.c_eval);
        transcript.append_scalar(b"left_sig_eval", &self.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &self.right_sigma_eval);
        transcript.append_scalar(b"z_hat_eval", &self.z_hat_eval);
        transcript.append_scalar(b"t_eval", &t_eval);
        transcript.append_scalar(b"r_eval", &self.lin_poly_eval);

        // Compute opening challenge
        let v = transcript.challenge_scalar(b"v");

        // Add commitment to openings to transcript
        transcript.append_commitment(b"w_z", &self.w_z_comm);
        transcript.append_commitment(b"w_z_w", &self.w_zw_comm);

        // Compute multi-point separation challenge
        let u = transcript.challenge_scalar(b"u");

        // Compute Partial Opening commitment
        let d_comm = self.compute_partial_opening_commitment(
            alpha,
            beta,
            gamma,
            z_challenge,
            u,
            v,
            l1_eval,
            &preprocessed_circuit,
        );

        // Compute batch opening commitment
        let f_comm =
            self.compute_batch_opening_commitment(z_challenge, v, d_comm, &preprocessed_circuit);

        // Compute batch evaluation commitment
        let e_comm = self.compute_batch_evaluation_commitment(
            z_challenge,
            u,
            v,
            t_eval,
            &preprocessed_circuit,
            &verifier_key,
        );

        // Validate

        let lhs = E::pairing(
            self.w_z_comm.0.into_projective() + &self.w_zw_comm.0.into_projective().mul(&u),
            verifier_key.beta_h,
        );

        let inner = {
            let k_0 = self.w_z_comm.0.into_projective().mul(&z_challenge);

            let u_z_root = u * &z_challenge * &domain.group_gen;
            let k_1 = self.w_zw_comm.0.into_projective().mul(&u_z_root);

            k_0 + &k_1 + &f_comm.into_projective() - &e_comm.into_projective()
        };

        let rhs = E::pairing(inner, verifier_key.h);

        lhs == rhs
    }

    fn compute_quotient_evaluation(
        &self,
        pi_eval: E::Fr,
        alpha: E::Fr,
        beta: E::Fr,
        gamma: E::Fr,
        l1_eval: E::Fr,
        z_h_eval: E::Fr,
        z_hat_eval: E::Fr,
    ) -> E::Fr {
        let alpha_sq = alpha.square();
        let alpha_cu = alpha_sq * &alpha;

        // r + PI(z) * alpha
        let a = self.lin_poly_eval + &(pi_eval * &alpha);

        // a + beta * sigma_1 + gamma
        let beta_sig1 = beta * &self.left_sigma_eval;
        let b_0 = self.a_eval + &beta_sig1 + &gamma;

        // b+ beta * sigma_2 + gamma
        let beta_sig2 = beta * &self.right_sigma_eval;
        let b_1 = self.b_eval + &beta_sig2 + &gamma;

        // ((c + gamma) * z_hat) * alpha^2
        let b_2 = (self.c_eval + &gamma) * &z_hat_eval * &alpha_sq;

        let b = b_0 * &b_1 * &b_2;

        // l_1(z) * alpha^3
        let c = l1_eval * &alpha_cu;

        let t_eval = (a - &b - &c) / &z_h_eval;

        t_eval
    }

    fn compute_partial_opening_commitment(
        &self,
        alpha: E::Fr,
        beta: E::Fr,
        gamma: E::Fr,
        z_challenge: E::Fr,
        u: E::Fr,
        v: E::Fr,
        l1_eval: E::Fr,
        preprocessed_circuit: &PreProcessedCircuit<E>,
    ) -> E::G1Affine {
        let k1 = E::Fr::multiplicative_generator();
        let k2 = E::Fr::from(13.into());

        let mut scalars: Vec<_> = Vec::with_capacity(6);
        let mut points: Vec<E::G1Affine> = Vec::with_capacity(6);

        scalars.push(self.a_eval * &self.b_eval * &alpha * &v);
        points.push(preprocessed_circuit.qm_comm().0);

        scalars.push(self.a_eval * &alpha * &v);
        points.push(preprocessed_circuit.ql_comm().0);

        scalars.push(self.b_eval * &alpha * &v);
        points.push(preprocessed_circuit.qr_comm().0);

        scalars.push(self.c_eval * &alpha * &v);
        points.push(preprocessed_circuit.qo_comm().0);

        scalars.push(E::Fr::one() * &alpha * &v);
        points.push(preprocessed_circuit.qc_comm().0);

        // (a_eval + beta * z + gamma)(b_eval + beta * z * k1 + gamma)(c_eval + beta * k2* z + gamma) * alpha^2 * v
        let q = {
            let beta_z = beta * &z_challenge;
            let q_0 = self.a_eval + &beta_z + &gamma;

            let beta_k1_z = beta * &k1 * &z_challenge;
            let q_1 = self.b_eval + &beta_k1_z + &gamma;

            let beta_k2_z = beta * &k2 * &z_challenge;
            let q_2 = (self.c_eval + &beta_k2_z + &gamma) * &alpha * &alpha * &v;

            q_0 * &q_1 * &q_2
        };
        // l1(z) * alpha^4 * v
        let r = l1_eval * &alpha.pow(&[4 as u64]) * &v;
        // v^7* u
        let s = v.pow(&[7 as u64]) * &u;

        scalars.push(q + &r + &s);
        points.push(self.z_comm.0);

        let scalars: Vec<_> = scalars.iter().map(|s| s.into_repr()).collect();

        VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine()
    }
    fn compute_batch_opening_commitment(
        &self,
        z_challenge: E::Fr,
        v: E::Fr,
        d_comm: E::G1Affine,
        preprocessed_circuit: &PreProcessedCircuit<E>,
    ) -> E::G1Affine {
        let mut scalars: Vec<_> = Vec::with_capacity(6);
        let mut points: Vec<E::G1Affine> = Vec::with_capacity(6);
        let n = preprocessed_circuit.n;

        let mut v_pow: Vec<E::Fr> = Vec::with_capacity(6);
        v_pow.push(E::Fr::one());
        for i in 1..=6 {
            v_pow.push(v_pow[i - 1] * &v);
        }

        let z_n = z_challenge.pow(&[n as u64]);
        let z_two_n = z_challenge.pow(&[2 * n as u64]);

        scalars.push(E::Fr::one());
        points.push(self.t_lo_comm.0);

        scalars.push(z_n);
        points.push(self.t_mid_comm.0);

        scalars.push(z_two_n);
        points.push(self.t_hi_comm.0);

        scalars.extend(v_pow);
        points.extend(vec![
            d_comm,
            self.a_comm.0,
            self.b_comm.0,
            self.c_comm.0,
            preprocessed_circuit.left_sigma_comm().0,
            preprocessed_circuit.right_sigma_comm().0,
        ]);

        let scalars: Vec<_> = scalars.iter().map(|s| s.into_repr()).collect();

        VariableBaseMSM::multi_scalar_mul(&points, &scalars).into_affine()
    }
    fn compute_batch_evaluation_commitment(
        &self,
        z_challenge: E::Fr,
        u: E::Fr,
        v: E::Fr,
        t_eval: E::Fr,
        preprocessed_circuit: &PreProcessedCircuit<E>,
        vk: &VerifierKey<E>,
    ) -> E::G1Affine {
        let n = preprocessed_circuit.n;

        let mut v_pow: Vec<E::Fr> = Vec::with_capacity(6);
        v_pow.push(E::Fr::one());
        for i in 1..=7 {
            v_pow.push(v_pow[i - 1] * &v);
        }

        // All components of batch evaluation commitment after the quotient evaluation, without the opening challenge
        let x = vec![
            self.lin_poly_eval,
            self.a_eval,
            self.b_eval,
            self.c_eval,
            self.left_sigma_eval,
            self.right_sigma_eval,
            (u * &self.z_hat_eval),
        ];

        let mut result = t_eval;
        for (i, j) in v_pow.into_iter().zip(x.iter()) {
            result += &(i * j);
        }

        vk.g.into_projective().mul(&result).into_affine()
    }
}
