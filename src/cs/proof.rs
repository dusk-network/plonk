use super::PreProcessedCircuit;
use crate::transcript::TranscriptProtocol;
use algebra::curves::PairingEngine;
use algebra::{
    biginteger::BigInteger256 as BigInteger,
    curves::{AffineCurve, ProjectiveCurve},
    fields::{Field, PrimeField},
    groups::Group,
    msm::VariableBaseMSM,
};

use ff_fft::DensePolynomial as Polynomial;
use ff_fft::EvaluationDomain;
use num_traits::{One, Zero};
use poly_commit::data_structures::PCCommitment;
use poly_commit::kzg10::{Commitment, VerifierKey};

#[derive(Clone)]
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
    // XXX: Need to confirm that for custom gates we do need more commitments for custom selector polynomial, as the selector polynomial is a part of the circuit description
    // Furthermore, we may not need any extra commitments as the checks are baked into the quotient polynomial and the setup elements can be put into the witness polynomials
}

impl<E: PairingEngine> Proof<E> {
    pub fn empty() -> Proof<E> {
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
        }
    }

    // Includes the commitments to the witness polynomials for left
    // right and output wires in the proof
    pub fn set_witness_poly_commitments(
        &mut self,
        a_comm: &Commitment<E>,
        b_comm: &Commitment<E>,
        c_comm: &Commitment<E>,
    ) -> () {
        self.a_comm = *a_comm;
        self.b_comm = *b_comm;
        self.c_comm = *c_comm;
    }

    // Includes the commitment to the permutation polynomial in the proof
    pub fn set_perm_poly_commitment(&mut self, z_comm: &Commitment<E>) -> () {
        self.z_comm = *z_comm;
    }

    // Includes the commitments to the quotient polynomials in the proof
    pub fn set_quotient_poly_commitments(
        &mut self,
        t_lo_comm: &Commitment<E>,
        t_mid_comm: &Commitment<E>,
        t_hi_comm: &Commitment<E>,
    ) -> () {
        self.t_lo_comm = *t_lo_comm;
        self.t_mid_comm = *t_mid_comm;
        self.t_hi_comm = *t_hi_comm;
    }

    // Includes the commitments to the opening polynomial and the shifted
    // opening polynomial in the proof
    pub fn set_opening_poly_commitments(
        &mut self,
        opening_poly_comm: &Commitment<E>,
        shifted_opening_poly_comm: &Commitment<E>,
    ) -> () {
        self.w_z_comm = *opening_poly_comm;
        self.w_zw_comm = *shifted_opening_poly_comm;
    }

    // Includes the evaluations of the witness polynomials at `z`
    // for left right and output wires in the proof
    pub fn set_witness_poly_evals(&mut self, a_eval: &E::Fr, b_eval: &E::Fr, c_eval: &E::Fr) -> () {
        self.a_eval = *a_eval;
        self.b_eval = *b_eval;
        self.c_eval = *c_eval;
    }

    // Includes the evaluation of the left and right sigma permutation
    // polynomials at `z` in the proof
    pub fn set_sigma_poly_evals(&mut self, left_sigm_eval: &E::Fr, right_sigm_eval: &E::Fr) -> () {
        self.left_sigma_eval = *left_sigm_eval;
        self.right_sigma_eval = *right_sigm_eval;
    }

    // Includes the evaluation of the linearisation sigma polynomial at `z`
    // in the proof
    pub fn set_linearisation_poly_eval(&mut self, lin_poly_eval: &E::Fr) -> () {
        self.lin_poly_eval = *lin_poly_eval;
    }

    // Includes the (Shifted) Evaluation of the permutation polynomial at
    // `z * root of unity` in the proof
    pub fn set_shifted_perm_poly_eval(&mut self, shft_perm_poly_eval: &E::Fr) -> () {
        self.z_hat_eval = *shft_perm_poly_eval;
    }

    pub fn verify(
        &self,
        preprocessed_circuit: &PreProcessedCircuit<E>,
        transcript: &mut dyn TranscriptProtocol<E>,
        verifier_key: &VerifierKey<E>,
        pub_inputs: &Vec<E::Fr>,
    ) -> bool {
        use bench_utils::*;

        let init_time = start_timer!(|| "Transcript Setup");
        let domain = EvaluationDomain::new(preprocessed_circuit.n).unwrap();

        // XXX: Check if components are valid

        // Add witness polynomials to transcript
        transcript.append_commitment(b"w_l", &self.a_comm);
        transcript.append_commitment(b"w_r", &self.b_comm);
        transcript.append_commitment(b"w_o", &self.c_comm);

        // Compute beta and gamma
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
        end_timer!(init_time);

        let init_time_2 = start_timer!(|| "Evaluate vanishing poly");
        // Compute zero polynomial evaluated at `z_challenge`
        let z_h_eval = domain.evaluate_vanishing_polynomial(z_challenge);
        end_timer!(init_time_2);

        let init_time_2 = start_timer!(|| "Evaluate lagrange coeffs");
        // Compute first lagrange polynomial evaluated at `z_challenge`

        let n_fr = E::Fr::from_repr((domain.size() as u64).into());
        let denom = n_fr * &(z_challenge - &E::Fr::one());
        let l1_eval = z_h_eval / &denom;
        end_timer!(init_time_2);

        let init_time_2 = start_timer!(|| "Compute PI eval at z_challenge");
        // Compute the public input polynomial evaluated at `z_challenge`
        let pi_poly = Polynomial::from_coefficients_vec(domain.ifft(&pub_inputs));
        let mut sparse_pi_poly: SparsePolynomial<E> = SparsePolynomial::new();
        sparse_pi_poly.from_dense_polynomial(&pi_poly);
        let pi_eval = sparse_pi_poly.evaluate(z_challenge);
        end_timer!(init_time_2);

        let init_time_2 = start_timer!(|| "Compute quotient poly eval at z_challenge");
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
        end_timer!(init_time_2);

        let init_time_2 = start_timer!(|| "Add evals to transcript");
        // Add evaluations to transcript
        transcript.append_scalar(b"a_eval", &self.a_eval);
        transcript.append_scalar(b"b_eval", &self.b_eval);
        transcript.append_scalar(b"c_eval", &self.c_eval);
        transcript.append_scalar(b"left_sig_eval", &self.left_sigma_eval);
        transcript.append_scalar(b"right_sig_eval", &self.right_sigma_eval);
        transcript.append_scalar(b"perm_eval", &self.z_hat_eval);
        transcript.append_scalar(b"t_eval", &t_eval);
        transcript.append_scalar(b"r_eval", &self.lin_poly_eval);

        // Compute opening challenge
        let v = transcript.challenge_scalar(b"v");
        // Add commitment to openings to transcript
        transcript.append_commitment(b"w_z", &self.w_z_comm);
        transcript.append_commitment(b"w_z_w", &self.w_zw_comm);

        // Compute multi-point separation challenge
        let u = transcript.challenge_scalar(b"u");

        end_timer!(init_time_2);
        let init_time_2 = start_timer!(|| "Compute partial opening commitment");
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

        end_timer!(init_time_2);
        let init_time_2 = start_timer!(|| "Compute batch opening commitment");
        // Compute batch opening commitment
        let f_comm = self.compute_batch_opening_commitment(
            z_challenge,
            v,
            d_comm.into_affine(),
            &preprocessed_circuit,
        );

        end_timer!(init_time_2);
        let init_time_2 = start_timer!(|| "Compute batch evaluation commitment");
        // Compute batch evaluation commitment
        let e_comm = self.compute_batch_evaluation_commitment(u, v, t_eval, &verifier_key);
        end_timer!(init_time_2);
        // Validate

        let init_time_2 = start_timer!(|| "Pairing validation");
        let lhs = E::pairing(
            self.w_z_comm.0.into_projective() + &self.w_zw_comm.0.into_projective().mul(&u),
            verifier_key.beta_h,
        );

        let inner = {
            let k_0 = self.w_z_comm.0.into_projective().mul(&z_challenge);

            let u_z_root = u * &z_challenge * &domain.group_gen;
            let k_1 = self.w_zw_comm.0.into_projective().mul(&u_z_root);

            k_0 + &k_1 + &f_comm - &e_comm
        };

        let rhs = E::pairing(inner, verifier_key.h);
        end_timer!(init_time_2);
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
    ) -> E::G1Projective {
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

        scalars.push(alpha * &v);
        points.push(preprocessed_circuit.qc_comm().0);

        // (a_eval + beta * z + gamma)(b_eval + beta * z * k1 + gamma)(c_eval + beta * k2* z + gamma) * alpha^2 * v
        let x = {
            let beta_z = beta * &z_challenge;
            let q_0 = self.a_eval + &beta_z + &gamma;

            let beta_k1_z = beta * &k1 * &z_challenge;
            let q_1 = self.b_eval + &beta_k1_z + &gamma;

            let beta_k2_z = beta * &k2 * &z_challenge;
            let q_2 = (self.c_eval + &beta_k2_z + &gamma) * &alpha * &alpha * &v;

            q_0 * &q_1 * &q_2
        };

        // l1(z) * alpha^3 * v
        let r = l1_eval * &alpha.pow(&[3 as u64]) * &v;
        // v^7* u
        let s = v.pow(&[7 as u64]) * &u;

        scalars.push(x + &r + &s);
        points.push(self.z_comm.0);

        // (a_eval + beta * sigma_1_eval + gamma)(b_eval + beta * sigma_2_eval + gamma)(c_eval + beta * sigma_3_eval + gamma) *alpha^2 * v
        let y = {
            let beta_sigma_1 = beta * &self.left_sigma_eval;
            let q_0 = self.a_eval + &beta_sigma_1 + &gamma;

            let beta_sigma_2 = beta * &self.right_sigma_eval;
            let q_1 = self.b_eval + &beta_sigma_2 + &gamma;

            let q_2 = beta * &self.z_hat_eval * &alpha * &alpha * &v;

            q_0 * &q_1 * &q_2
        };
        scalars.push(-y);
        points.push(preprocessed_circuit.out_sigma_comm().0);

        let scalars: Vec<_> = scalars.iter().map(|s| s.into_repr()).collect();

        VariableBaseMSM::multi_scalar_mul(&points, &scalars)
    }
    fn compute_batch_opening_commitment(
        &self,
        z_challenge: E::Fr,
        v: E::Fr,
        d_comm: E::G1Affine,
        preprocessed_circuit: &PreProcessedCircuit<E>,
    ) -> E::G1Projective {
        let mut scalars: Vec<_> = Vec::with_capacity(6);
        let mut points: Vec<E::G1Affine> = Vec::with_capacity(6);
        let n = preprocessed_circuit.n;

        let z_n = z_challenge.pow(&[n as u64]);
        let z_two_n = z_challenge.pow(&[2 * n as u64]);

        scalars.push(E::Fr::one());
        points.push(self.t_lo_comm.0);

        scalars.push(z_n);
        points.push(self.t_mid_comm.0);

        scalars.push(z_two_n);
        points.push(self.t_hi_comm.0);

        scalars.push(E::Fr::one());
        points.push(d_comm);

        scalars.push(v.pow(&[2 as u64]));
        points.push(self.a_comm.0);

        scalars.push(v.pow(&[3 as u64]));
        points.push(self.b_comm.0);

        scalars.push(v.pow(&[4 as u64]));
        points.push(self.c_comm.0);

        scalars.push(v.pow(&[5 as u64]));
        points.push(preprocessed_circuit.left_sigma_comm().0);

        scalars.push(v.pow(&[6 as u64]));
        points.push(preprocessed_circuit.right_sigma_comm().0);

        let scalars: Vec<_> = scalars.iter().map(|s| s.into_repr()).collect();

        VariableBaseMSM::multi_scalar_mul(&points, &scalars)
    }
    fn compute_batch_evaluation_commitment(
        &self,
        u: E::Fr,
        v: E::Fr,
        t_eval: E::Fr,
        vk: &VerifierKey<E>,
    ) -> E::G1Projective {
        let x = vec![
            (E::Fr::one(), t_eval),
            (v, self.lin_poly_eval),
            (v.pow(&[2 as u64]), self.a_eval),
            (v.pow(&[3 as u64]), self.b_eval),
            (v.pow(&[4 as u64]), self.c_eval),
            (v.pow(&[5 as u64]), self.left_sigma_eval),
            (v.pow(&[6 as u64]), self.right_sigma_eval),
            (v.pow(&[7 as u64]), u * &self.z_hat_eval),
        ];

        let mut result = E::Fr::zero();
        for (i, j) in x.iter() {
            result += &(*i * j);
        }

        vk.g.into_projective().mul(&result)
    }
}
use std::marker::PhantomData;

struct SparsePolynomial<'a, E: PairingEngine> {
    _engine: PhantomData<E>,
    coeffs: Vec<(usize, &'a E::Fr)>,
}

impl<'a, E: PairingEngine> SparsePolynomial<'a, E> {
    pub fn new() -> Self {
        SparsePolynomial {
            _engine: PhantomData,
            coeffs: Vec::new(),
        }
    }

    fn from_dense_polynomial(&mut self, p: &'a Polynomial<E::Fr>) {
        let mut sparse_coeffs: Vec<(usize, &E::Fr)> = Vec::new();

        for (index, scalar) in p.coeffs.iter().enumerate() {
            if !scalar.is_zero() {
                self.coeffs.push((index, scalar))
            }
        }
    }
    fn evaluate(&self, point: E::Fr) -> E::Fr {
        let mut result = E::Fr::zero();

        for (index, coeff) in self.coeffs.iter() {
            let power = point.pow(&[*index as u64]);
            result += &(power * coeff);
        }
        result
    }
}
