// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Methods to preprocess the constraint system for use in a proof

use crate::commitment_scheme::kzg10::CommitKey;
use crate::constraint_system::StandardComposer;
use crate::plookup::PreprocessedTable4Arity;

use crate::error::Error;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::proof_system::{widget, ProverKey};
use dusk_bls12_381::BlsScalar;
use merlin::Transcript;

/// Struct that contains all of the selector and permutation [`Polynomial`]s in
/// PLONK.
pub(crate) struct SelectorPolynomials {
    q_m: Polynomial,
    q_l: Polynomial,
    q_r: Polynomial,
    q_o: Polynomial,
    q_c: Polynomial,
    q_4: Polynomial,
    q_arith: Polynomial,
    q_range: Polynomial,
    q_logic: Polynomial,
    q_fixed_group_add: Polynomial,
    q_variable_group_add: Polynomial,
    q_lookup: Polynomial,

    left_sigma: Polynomial,
    right_sigma: Polynomial,
    out_sigma: Polynomial,
    fourth_sigma: Polynomial,
}

impl StandardComposer {
    /// Pads the circuit to the next power of two.
    ///
    /// # Note
    /// `diff` is the difference between circuit size and next power of two.
    fn pad(&mut self, diff: usize) {
        // Add a zero variable to circuit
        let zero_scalar = BlsScalar::zero();
        let zero_var = self.zero_var();

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
        self.q_lookup.extend(zeroes_scalar.iter());

        self.w_l.extend(zeroes_var.iter());
        self.w_r.extend(zeroes_var.iter());
        self.w_o.extend(zeroes_var.iter());
        self.w_4.extend(zeroes_var.iter());

        self.n += diff;
    }

    /// Checks that all of the wires of the composer have the same
    /// length.
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
            && self.q_lookup.len() == k
            && self.w_l.len() == k
            && self.w_r.len() == k
            && self.w_o.len() == k
            && self.w_4.len() == k
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
    pub fn preprocess_prover(
        &mut self,
        commit_key: &CommitKey,
        transcript: &mut Transcript,
    ) -> Result<ProverKey, Error> {
        let (_, selectors, preprocessed_table, domain) =
            self.preprocess_shared(commit_key, transcript)?;

        let domain_4n = EvaluationDomain::new(4 * domain.size())?;
        let q_m_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_m),
            domain_4n,
        );
        let q_l_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_l),
            domain_4n,
        );
        let q_r_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_r),
            domain_4n,
        );
        let q_o_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_o),
            domain_4n,
        );
        let q_c_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_c),
            domain_4n,
        );
        let q_4_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_4),
            domain_4n,
        );
        let q_arith_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_arith),
            domain_4n,
        );
        let q_range_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_range),
            domain_4n,
        );
        let q_logic_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_logic),
            domain_4n,
        );
        let q_fixed_group_add_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_fixed_group_add),
            domain_4n,
        );
        let q_variable_group_add_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_variable_group_add),
            domain_4n,
        );
        let q_lookup_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.q_lookup),
            domain_4n,
        );

        let left_sigma_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.left_sigma),
            domain_4n,
        );
        let right_sigma_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.right_sigma),
            domain_4n,
        );
        let out_sigma_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.out_sigma),
            domain_4n,
        );
        let fourth_sigma_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&selectors.fourth_sigma),
            domain_4n,
        );

        let table_1_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&preprocessed_table.t_1.2),
            domain_4n,
        );
        let table_2_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&preprocessed_table.t_2.2),
            domain_4n,
        );
        let table_3_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&preprocessed_table.t_3.2),
            domain_4n,
        );
        let table_4_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&preprocessed_table.t_4.2),
            domain_4n,
        );

        // XXX: Remove this and compute it on the fly
        let linear_eval_4n = Evaluations::from_vec_and_domain(
            domain_4n.coset_fft(&[BlsScalar::zero(), BlsScalar::one()]),
            domain_4n,
        );

        // Prover Key for arithmetic circuits
        let arithmetic_prover_key = widget::arithmetic::ProverKey {
            q_m: (selectors.q_m, q_m_eval_4n),
            q_l: (selectors.q_l.clone(), q_l_eval_4n.clone()),
            q_r: (selectors.q_r.clone(), q_r_eval_4n.clone()),
            q_o: (selectors.q_o, q_o_eval_4n),
            q_c: (selectors.q_c.clone(), q_c_eval_4n.clone()),
            q_4: (selectors.q_4, q_4_eval_4n),
            q_arith: (selectors.q_arith, q_arith_eval_4n),
        };

        // Prover Key for range circuits
        let range_prover_key = widget::range::ProverKey {
            q_range: (selectors.q_range, q_range_eval_4n),
        };

        // Prover Key for logic circuits
        let logic_prover_key = widget::logic::ProverKey {
            q_c: (selectors.q_c.clone(), q_c_eval_4n.clone()),
            q_logic: (selectors.q_logic, q_logic_eval_4n),
        };

        // Prover Key for ecc circuits
        let ecc_prover_key = widget::ecc::scalar_mul::fixed_base::ProverKey {
            q_l: (selectors.q_l, q_l_eval_4n),
            q_r: (selectors.q_r, q_r_eval_4n),
            q_c: (selectors.q_c, q_c_eval_4n),
            q_fixed_group_add: (
                selectors.q_fixed_group_add,
                q_fixed_group_add_eval_4n,
            ),
        };

        // Prover Key for permutation argument
        let permutation_prover_key = widget::permutation::ProverKey {
            left_sigma: (selectors.left_sigma, left_sigma_eval_4n),
            right_sigma: (selectors.right_sigma, right_sigma_eval_4n),
            out_sigma: (selectors.out_sigma, out_sigma_eval_4n),
            fourth_sigma: (selectors.fourth_sigma, fourth_sigma_eval_4n),
            linear_evaluations: linear_eval_4n,
        };

        // Prover Key for curve addition
        let curve_addition_prover_key =
            widget::ecc::curve_addition::ProverKey {
                q_variable_group_add: (
                    selectors.q_variable_group_add,
                    q_variable_group_add_eval_4n,
                ),
            };

        // Prover key for lookup operations
        let lookup_prover_key = widget::lookup::ProverKey {
            q_lookup: (selectors.q_lookup, q_lookup_eval_4n),
            table_1: (
                preprocessed_table.t_1.0,
                preprocessed_table.t_1.2,
                table_1_eval_4n,
            ),
            table_2: (
                preprocessed_table.t_2.0,
                preprocessed_table.t_2.2,
                table_2_eval_4n,
            ),
            table_3: (
                preprocessed_table.t_3.0,
                preprocessed_table.t_3.2,
                table_3_eval_4n,
            ),
            table_4: (
                preprocessed_table.t_4.0,
                preprocessed_table.t_4.2,
                table_4_eval_4n,
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
            lookup: lookup_prover_key,
            // Compute 4n evaluations for X^n -1
            v_h_coset_4n: domain_4n
                .compute_vanishing_poly_over_coset(domain.size() as u64),
        };

        Ok(prover_key)
    }

    /// The verifier only requires the commitments in order to verify a
    /// [`Proof`](super::Proof) We can therefore speed up preprocessing for the
    /// verifier by skipping the FFTs needed to compute the 4n evaluations.
    pub fn preprocess_verifier(
        &mut self,
        commit_key: &CommitKey,
        transcript: &mut Transcript,
    ) -> Result<widget::VerifierKey, Error> {
        let (verifier_key, _, _, _) =
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
    ) -> Result<
        (
            widget::VerifierKey,
            SelectorPolynomials,
            PreprocessedTable4Arity,
            EvaluationDomain,
        ),
        Error,
    > {
        let domain = EvaluationDomain::new(self.total_size())?;

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
        let q_lookup_poly =
            Polynomial::from_coefficients_slice(&domain.ifft(&self.q_lookup));

        // 2. Compute the sigma polynomials
        let (
            left_sigma_poly,
            right_sigma_poly,
            out_sigma_poly,
            fourth_sigma_poly,
        ) = self.perm.compute_sigma_polynomials(self.n, &domain);

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
        let q_lookup_poly_commit =
            commit_key.commit(&q_lookup_poly).unwrap_or_default();

        let left_sigma_poly_commit = commit_key.commit(&left_sigma_poly)?;
        let right_sigma_poly_commit = commit_key.commit(&right_sigma_poly)?;
        let out_sigma_poly_commit = commit_key.commit(&out_sigma_poly)?;
        let fourth_sigma_poly_commit = commit_key.commit(&fourth_sigma_poly)?;

        // Preprocess the lookup table
        let preprocessed_table = PreprocessedTable4Arity::preprocess(
            &self.lookup_table,
            &commit_key,
            domain.size() as u32,
        )?;

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

        // Verifier Key for lookup operations
        let lookup_verifier_key = widget::lookup::VerifierKey {
            q_lookup: q_lookup_poly_commit,
            table_1: preprocessed_table.t_1.1,
            table_2: preprocessed_table.t_2.1,
            table_3: preprocessed_table.t_3.1,
            table_4: preprocessed_table.t_4.1,
        };

        // Verifier Key for permutation argument
        let permutation_verifier_key = widget::permutation::VerifierKey {
            left_sigma: left_sigma_poly_commit,
            right_sigma: right_sigma_poly_commit,
            out_sigma: out_sigma_poly_commit,
            fourth_sigma: fourth_sigma_poly_commit,
        };

        let verifier_key = widget::VerifierKey {
            n: self.circuit_size(),
            arithmetic: arithmetic_verifier_key,
            logic: logic_verifier_key,
            range: range_verifier_key,
            fixed_base: ecc_verifier_key,
            variable_base: curve_addition_verifier_key,
            permutation: permutation_verifier_key,
            lookup: lookup_verifier_key,
        };

        let selectors = SelectorPolynomials {
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
            q_lookup: q_lookup_poly,
            left_sigma: left_sigma_poly,
            right_sigma: right_sigma_poly,
            out_sigma: out_sigma_poly,
            fourth_sigma: fourth_sigma_poly,
        };

        // Add the circuit description to the transcript
        verifier_key.seed_transcript(transcript);

        Ok((verifier_key, selectors, preprocessed_table, domain))
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::constraint_system::helper::*;
    #[test]
    /// Tests that the circuit gets padded to the correct length
    /// XXX: We can do this test without dummy_gadget method
    fn test_plookup_pad() {
        let mut composer: StandardComposer = StandardComposer::new();
        dummy_gadget_plookup(100, &mut composer);

        // Pad the circuit to next power of two
        let next_pow_2 = composer.n.next_power_of_two() as u64;
        composer.pad(next_pow_2 as usize - composer.n);

        let size = composer.n;
        assert!(size.is_power_of_two());
        assert!(composer.q_m.len() == size);
        assert!(composer.q_l.len() == size);
        assert!(composer.q_o.len() == size);
        assert!(composer.q_r.len() == size);
        assert!(composer.q_c.len() == size);
        assert!(composer.q_arith.len() == size);
        assert!(composer.q_range.len() == size);
        assert!(composer.q_logic.len() == size);
        assert!(composer.q_fixed_group_add.len() == size);
        assert!(composer.q_variable_group_add.len() == size);
        assert!(composer.q_lookup.len() == size);
        assert!(composer.w_l.len() == size);
        assert!(composer.w_r.len() == size);
        assert!(composer.w_o.len() == size);
    }
}
