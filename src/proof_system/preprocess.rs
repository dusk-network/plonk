// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Methods to preprocess the constraint system for use in a proof

use crate::commitment_scheme::CommitKey;
use crate::constraint_system::TurboComposer;

use crate::error::Error;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::proof_system::{widget, ProverKey};
use dusk_bls12_381::BlsScalar;
use merlin::Transcript;

/// Struct that contains all selector and permutation [`Polynomials`]s
pub(crate) struct Polynomials {
    // selector polynomials defining arithmetic circuits
    q_m: Polynomial,
    q_l: Polynomial,
    q_r: Polynomial,
    q_o: Polynomial,
    q_c: Polynomial,

    // additional selector for 3-input gates added for efficiency of
    // implementation
    q_4: Polynomial,

    // additional selectors for different kinds of circuits added for
    // efficiency of implementation
    q_arith: Polynomial,              // arithmetic circuits
    q_range: Polynomial,              // range proofs
    q_logic: Polynomial,              // boolean operations
    q_fixed_group_add: Polynomial,    // ecc circuits
    q_variable_group_add: Polynomial, // ecc circuits

    // copy permutation polynomials
    s_sigma_1: Polynomial,
    s_sigma_2: Polynomial,
    s_sigma_3: Polynomial,
    s_sigma_4: Polynomial, // for q_4
}

impl TurboComposer {
    /// Pads the circuit to the next power of two
    ///
    /// # Note:
    ///
    /// `diff` is the difference between circuit size and next power of two
    fn pad(&mut self, diff: usize) {
        // Add a zero variable to circuit
        let zero_scalar = BlsScalar::zero();
        let zero_var = Self::constant_zero();

        let zeroes_scalar = vec![zero_scalar; diff];
        let zeroes_var = vec![zero_var; diff];

        self.q_m.extend(zeroes_scalar.iter());
        self.q_l.extend(zeroes_scalar.iter());
        self.q_r.extend(zeroes_scalar.iter());
        self.q_o.extend(zeroes_scalar.iter());
        self.q_c.extend(zeroes_scalar.iter());
        self.q_4.extend(zeroes_scalar.iter());
        self.q_arith.extend(zeroes_scalar.iter());
        self.q_range.extend(zeroes_scalar.iter());
        self.q_logic.extend(zeroes_scalar.iter());
        self.q_fixed_group_add.extend(zeroes_scalar.iter());
        self.q_variable_group_add.extend(zeroes_scalar.iter());

        self.a_w.extend(zeroes_var.iter());
        self.b_w.extend(zeroes_var.iter());
        self.c_w.extend(zeroes_var.iter());
        self.d_w.extend(zeroes_var.iter());

        self.n += diff;
    }

    /// Checks that all of the wires of the composer have the same length.
    fn check_poly_same_len(&self) -> Result<(), Error> {
        let k = self.q_m.len();

        if self.q_o.len() == k
            && self.q_l.len() == k
            && self.q_r.len() == k
            && self.q_c.len() == k
            && self.q_4.len() == k
            && self.q_arith.len() == k
            && self.q_range.len() == k
            && self.q_logic.len() == k
            && self.q_fixed_group_add.len() == k
            && self.q_variable_group_add.len() == k
            && self.a_w.len() == k
            && self.b_w.len() == k
            && self.c_w.len() == k
            && self.d_w.len() == k
        {
            Ok(())
        } else {
            Err(Error::MismatchedPolyLen)
        }
    }

    /// These are the parts of preprocessing that the prover must compute
    /// Although the prover does not need the verification key, he must compute
    /// the commitments in order to seed the transcript, allowing both the
    /// prover and verifier to have the same view
    pub(crate) fn preprocess_prover(
        &mut self,
        commit_key: &CommitKey,
        transcript: &mut Transcript,
    ) -> Result<ProverKey, Error> {
        let (_, selectors, domain) =
            self.preprocess_shared(commit_key, transcript)?;

        // The polynomial needs an evaluation domain of 4n.
        // Plus, adding the blinding factors translates to
        // the polynomial not fitting in 4n, so now we need
        // 8n, the next power of 2
        let domain_8n = EvaluationDomain::new(8 * domain.size())?;
        let q_m_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_m),
            domain_8n,
        );
        let q_l_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_l),
            domain_8n,
        );
        let q_r_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_r),
            domain_8n,
        );
        let q_o_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_o),
            domain_8n,
        );
        let q_c_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_c),
            domain_8n,
        );
        let q_4_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_4),
            domain_8n,
        );
        let q_arith_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_arith),
            domain_8n,
        );
        let q_range_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_range),
            domain_8n,
        );
        let q_logic_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_logic),
            domain_8n,
        );
        let q_fixed_group_add_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_fixed_group_add),
            domain_8n,
        );
        let q_variable_group_add_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.q_variable_group_add),
            domain_8n,
        );

        let s_sigma_1_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.s_sigma_1),
            domain_8n,
        );
        let s_sigma_2_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.s_sigma_2),
            domain_8n,
        );
        let s_sigma_3_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.s_sigma_3),
            domain_8n,
        );
        let s_sigma_4_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&selectors.s_sigma_4),
            domain_8n,
        );

        // XXX: Remove this and compute it on the fly
        let linear_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&[BlsScalar::zero(), BlsScalar::one()]),
            domain_8n,
        );

        // Prover Key for arithmetic circuits
        let arithmetic_prover_key = widget::arithmetic::ProverKey {
            q_m: (selectors.q_m, q_m_eval_8n),
            q_l: (selectors.q_l.clone(), q_l_eval_8n.clone()),
            q_r: (selectors.q_r.clone(), q_r_eval_8n.clone()),
            q_o: (selectors.q_o, q_o_eval_8n),
            q_c: (selectors.q_c.clone(), q_c_eval_8n.clone()),
            q_4: (selectors.q_4, q_4_eval_8n),
            q_arith: (selectors.q_arith, q_arith_eval_8n),
        };

        // Prover Key for range circuits
        let range_prover_key = widget::range::ProverKey {
            q_range: (selectors.q_range, q_range_eval_8n),
        };

        // Prover Key for logic circuits
        let logic_prover_key = widget::logic::ProverKey {
            q_c: (selectors.q_c.clone(), q_c_eval_8n.clone()),
            q_logic: (selectors.q_logic, q_logic_eval_8n),
        };

        // Prover Key for ecc circuits
        let ecc_prover_key = widget::ecc::scalar_mul::fixed_base::ProverKey {
            q_l: (selectors.q_l, q_l_eval_8n),
            q_r: (selectors.q_r, q_r_eval_8n),
            q_c: (selectors.q_c, q_c_eval_8n),
            q_fixed_group_add: (
                selectors.q_fixed_group_add,
                q_fixed_group_add_eval_8n,
            ),
        };

        // Prover Key for permutation argument
        let permutation_prover_key = widget::permutation::ProverKey {
            s_sigma_1: (selectors.s_sigma_1, s_sigma_1_eval_8n),
            s_sigma_2: (selectors.s_sigma_2, s_sigma_2_eval_8n),
            s_sigma_3: (selectors.s_sigma_3, s_sigma_3_eval_8n),
            s_sigma_4: (selectors.s_sigma_4, s_sigma_4_eval_8n),
            linear_evaluations: linear_eval_8n,
        };

        // Prover Key for curve addition
        let curve_addition_prover_key =
            widget::ecc::curve_addition::ProverKey {
                q_variable_group_add: (
                    selectors.q_variable_group_add,
                    q_variable_group_add_eval_8n,
                ),
            };

        let prover_key = ProverKey {
            n: domain.size(),
            arithmetic: arithmetic_prover_key,
            logic: logic_prover_key,
            range: range_prover_key,
            permutation: permutation_prover_key,
            variable_base: curve_addition_prover_key,
            fixed_base: ecc_prover_key,
            // Compute 8n evaluations for X^n -1
            v_h_coset_8n: domain_8n
                .compute_vanishing_poly_over_coset(domain.size() as u64),
        };

        Ok(prover_key)
    }

    /// The verifier only requires the commitments in order to verify a
    /// [`Proof`](super::Proof) We can therefore speed up preprocessing for the
    /// verifier by skipping the FFTs needed to compute the 8n evaluations.
    pub(crate) fn preprocess_verifier(
        &mut self,
        commit_key: &CommitKey,
        transcript: &mut Transcript,
    ) -> Result<widget::VerifierKey, Error> {
        let (verifier_key, _, _) =
            self.preprocess_shared(commit_key, transcript)?;
        Ok(verifier_key)
    }

    /// Both the [`Prover`](super::Prover) and [`Verifier`](super::Verifier)
    /// must perform IFFTs on the selector polynomials and permutation
    /// polynomials in order to commit to them and have the same transcript
    /// view.
    fn preprocess_shared(
        &mut self,
        commit_key: &CommitKey,
        transcript: &mut Transcript,
    ) -> Result<(widget::VerifierKey, Polynomials, EvaluationDomain), Error>
    {
        let domain = EvaluationDomain::new(self.n)?;

        // Check that the length of the wires is consistent.
        self.check_poly_same_len()?;

        // 1. Pad circuit to a power of two
        self.pad(domain.size as usize - self.n);

        let q_m_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_m));
        let q_l_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_l));
        let q_r_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_r));
        let q_o_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_o));
        let q_c_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_c));
        let q_4_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_4));
        let q_arith_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_arith));
        let q_range_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_range));
        let q_logic_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_logic));
        let q_fixed_group_add_poly = Polynomial::from_coefficients_slice(
            &domain.ifft(&self.q_fixed_group_add),
        );
        let q_variable_group_add_poly = Polynomial::from_coefficients_slice(
            &domain.ifft(&self.q_variable_group_add),
        );

        // 2. Compute the sigma polynomials
        let [s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly] =
            self.perm.compute_sigma_polynomials(self.n, &domain);

        let q_m_poly_commit = commit_key.commit(&q_m_poly).unwrap_or_default();
        let q_l_poly_commit = commit_key.commit(&q_l_poly).unwrap_or_default();
        let q_r_poly_commit = commit_key.commit(&q_r_poly).unwrap_or_default();
        let q_o_poly_commit = commit_key.commit(&q_o_poly).unwrap_or_default();
        let q_c_poly_commit = commit_key.commit(&q_c_poly).unwrap_or_default();
        let q_4_poly_commit = commit_key.commit(&q_4_poly).unwrap_or_default();
        let q_arith_poly_commit =
            commit_key.commit(&q_arith_poly).unwrap_or_default();
        let q_range_poly_commit =
            commit_key.commit(&q_range_poly).unwrap_or_default();
        let q_logic_poly_commit =
            commit_key.commit(&q_logic_poly).unwrap_or_default();
        let q_fixed_group_add_poly_commit = commit_key
            .commit(&q_fixed_group_add_poly)
            .unwrap_or_default();
        let q_variable_group_add_poly_commit = commit_key
            .commit(&q_variable_group_add_poly)
            .unwrap_or_default();

        let s_sigma_1_poly_commit = commit_key.commit(&s_sigma_1_poly)?;
        let s_sigma_2_poly_commit = commit_key.commit(&s_sigma_2_poly)?;
        let s_sigma_3_poly_commit = commit_key.commit(&s_sigma_3_poly)?;
        let s_sigma_4_poly_commit = commit_key.commit(&s_sigma_4_poly)?;

        // Verifier Key for arithmetic circuits
        let arithmetic_verifier_key = widget::arithmetic::VerifierKey {
            q_m: q_m_poly_commit,
            q_l: q_l_poly_commit,
            q_r: q_r_poly_commit,
            q_o: q_o_poly_commit,
            q_c: q_c_poly_commit,
            q_4: q_4_poly_commit,
            q_arith: q_arith_poly_commit,
        };
        // Verifier Key for range circuits
        let range_verifier_key = widget::range::VerifierKey {
            q_range: q_range_poly_commit,
        };
        // Verifier Key for logic circuits
        let logic_verifier_key = widget::logic::VerifierKey {
            q_c: q_c_poly_commit,
            q_logic: q_logic_poly_commit,
        };
        // Verifier Key for ecc circuits
        let ecc_verifier_key =
            widget::ecc::scalar_mul::fixed_base::VerifierKey {
                q_l: q_l_poly_commit,
                q_r: q_r_poly_commit,
                q_fixed_group_add: q_fixed_group_add_poly_commit,
            };
        // Verifier Key for curve addition circuits
        let curve_addition_verifier_key =
            widget::ecc::curve_addition::VerifierKey {
                q_variable_group_add: q_variable_group_add_poly_commit,
            };

        // Verifier Key for permutation argument
        let permutation_verifier_key = widget::permutation::VerifierKey {
            s_sigma_1: s_sigma_1_poly_commit,
            s_sigma_2: s_sigma_2_poly_commit,
            s_sigma_3: s_sigma_3_poly_commit,
            s_sigma_4: s_sigma_4_poly_commit,
        };

        let verifier_key = widget::VerifierKey {
            n: self.gates(),
            arithmetic: arithmetic_verifier_key,
            logic: logic_verifier_key,
            range: range_verifier_key,
            fixed_base: ecc_verifier_key,
            variable_base: curve_addition_verifier_key,
            permutation: permutation_verifier_key,
        };

        let selectors = Polynomials {
            q_m: q_m_poly,
            q_l: q_l_poly,
            q_r: q_r_poly,
            q_o: q_o_poly,
            q_c: q_c_poly,
            q_4: q_4_poly,
            q_arith: q_arith_poly,
            q_range: q_range_poly,
            q_logic: q_logic_poly,
            q_fixed_group_add: q_fixed_group_add_poly,
            q_variable_group_add: q_variable_group_add_poly,
            s_sigma_1: s_sigma_1_poly,
            s_sigma_2: s_sigma_2_poly,
            s_sigma_3: s_sigma_3_poly,
            s_sigma_4: s_sigma_4_poly,
        };

        // Add the circuit description to the transcript
        verifier_key.seed_transcript(transcript);

        Ok((verifier_key, selectors, domain))
    }
}
