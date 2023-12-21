// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;

use crate::commitment_scheme::{CommitKey, OpeningKey, PublicParameters};
use crate::constraint_system::{Constraint, Selector, Witness};
use crate::error::Error;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::proof_system::preprocess::Polynomials;
use crate::proof_system::{widget, ProverKey};

use super::{Circuit, Composer, Gate, Prover, Verifier};

#[cfg(feature = "alloc")]
mod compress;

/// Generate the arguments to prove and verify a circuit
pub struct Compiler;

impl Compiler {
    /// Create a new arguments set from a given circuit instance
    ///
    /// Use the default implementation of the circuit
    pub fn compile<C>(
        pp: &PublicParameters,
        label: &[u8],
    ) -> Result<(Prover, Verifier), Error>
    where
        C: Circuit,
    {
        let mut composer = Composer::initialized();
        C::default().circuit(&mut composer)?;

        Self::compile_with_composer(pp, label, &composer)
    }

    /// Create a new arguments set from a given circuit instance
    ///
    /// Use the provided circuit instead of the default implementation
    pub fn compile_with_circuit<C>(
        pp: &PublicParameters,
        label: &[u8],
        circuit: &C,
    ) -> Result<(Prover, Verifier), Error>
    where
        C: Circuit,
    {
        let mut composer = Composer::initialized();
        circuit.circuit(&mut composer)?;

        Self::compile_with_composer(pp, label, &composer)
    }

    /// Return a bytes representation of a compressed circuit, capable of
    /// generating its prover and verifier instances.
    #[cfg(feature = "alloc")]
    pub fn compress<C>() -> Result<Vec<u8>, Error>
    where
        C: Circuit,
    {
        compress::CompressedCircuit::from_circuit::<C>(true)
    }

    /// Generates a [Prover] and [Verifier] from a buffer created by
    /// [Self::compress].
    pub fn decompress(
        pp: &PublicParameters,
        label: &[u8],
        compressed: &[u8],
    ) -> Result<(Prover, Verifier), Error> {
        compress::CompressedCircuit::from_bytes(pp, label, compressed)
    }

    /// Create a new arguments set from a given circuit instance
    ///
    /// Use the default implementation of the circuit
    fn compile_with_composer(
        pp: &PublicParameters,
        label: &[u8],
        composer: &Composer,
    ) -> Result<(Prover, Verifier), Error> {
        let n = (composer.constraints() + 6).next_power_of_two();

        let (commit, opening) = pp.trim(n)?;

        let (prover, verifier) =
            Self::preprocess(label, commit, opening, composer)?;

        Ok((prover, verifier))
    }

    fn preprocess(
        label: &[u8],
        commit_key: CommitKey,
        opening_key: OpeningKey,
        prover: &Composer,
    ) -> Result<(Prover, Verifier), Error> {
        let mut perm = prover.perm.clone();

        let constraints = prover.constraints();
        let size = constraints.next_power_of_two();

        let domain = EvaluationDomain::new(size - 1)?;

        // 1. pad circuit to a power of two
        //
        // we use allocated vectors because the current ifft api only accepts
        // slices
        let mut q_m = vec![BlsScalar::zero(); size];
        let mut q_l = vec![BlsScalar::zero(); size];
        let mut q_r = vec![BlsScalar::zero(); size];
        let mut q_o = vec![BlsScalar::zero(); size];
        let mut q_4 = vec![BlsScalar::zero(); size];
        let mut q_c = vec![BlsScalar::zero(); size];
        let mut q_arith = vec![BlsScalar::zero(); size];
        let mut q_range = vec![BlsScalar::zero(); size];
        let mut q_logic = vec![BlsScalar::zero(); size];
        let mut q_fixed_group_add = vec![BlsScalar::zero(); size];
        let mut q_variable_group_add = vec![BlsScalar::zero(); size];

        prover.constraints.iter().enumerate().for_each(|(i, c)| {
            q_m[i] = c.q_m;
            q_l[i] = c.q_l;
            q_r[i] = c.q_r;
            q_o[i] = c.q_o;
            q_4[i] = c.q_4;
            q_c[i] = c.q_c;
            q_arith[i] = c.q_arith;
            q_range[i] = c.q_range;
            q_logic[i] = c.q_logic;
            q_fixed_group_add[i] = c.q_fixed_group_add;
            q_variable_group_add[i] = c.q_variable_group_add;
        });

        let q_m_poly = domain.ifft(&q_m);
        let q_l_poly = domain.ifft(&q_l);
        let q_r_poly = domain.ifft(&q_r);
        let q_o_poly = domain.ifft(&q_o);
        let q_4_poly = domain.ifft(&q_4);
        let q_c_poly = domain.ifft(&q_c);
        let q_arith_poly = domain.ifft(&q_arith);
        let q_range_poly = domain.ifft(&q_range);
        let q_logic_poly = domain.ifft(&q_logic);
        let q_fixed_group_add_poly = domain.ifft(&q_fixed_group_add);
        let q_variable_group_add_poly = domain.ifft(&q_variable_group_add);

        let q_m_poly = Polynomial::from_coefficients_vec(q_m_poly);
        let q_l_poly = Polynomial::from_coefficients_vec(q_l_poly);
        let q_r_poly = Polynomial::from_coefficients_vec(q_r_poly);
        let q_o_poly = Polynomial::from_coefficients_vec(q_o_poly);
        let q_4_poly = Polynomial::from_coefficients_vec(q_4_poly);
        let q_c_poly = Polynomial::from_coefficients_vec(q_c_poly);
        let q_arith_poly = Polynomial::from_coefficients_vec(q_arith_poly);
        let q_range_poly = Polynomial::from_coefficients_vec(q_range_poly);
        let q_logic_poly = Polynomial::from_coefficients_vec(q_logic_poly);
        let q_fixed_group_add_poly =
            Polynomial::from_coefficients_vec(q_fixed_group_add_poly);
        let q_variable_group_add_poly =
            Polynomial::from_coefficients_vec(q_variable_group_add_poly);

        // 2. compute the sigma polynomials
        let [s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly] =
            perm.compute_sigma_polynomials(size, &domain);

        let q_m_poly_commit = commit_key.commit(&q_m_poly).unwrap_or_default();
        let q_l_poly_commit = commit_key.commit(&q_l_poly).unwrap_or_default();
        let q_r_poly_commit = commit_key.commit(&q_r_poly).unwrap_or_default();
        let q_o_poly_commit = commit_key.commit(&q_o_poly).unwrap_or_default();
        let q_4_poly_commit = commit_key.commit(&q_4_poly).unwrap_or_default();
        let q_c_poly_commit = commit_key.commit(&q_c_poly).unwrap_or_default();
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

        // verifier Key for arithmetic circuits
        let arithmetic_verifier_key = widget::arithmetic::VerifierKey {
            q_m: q_m_poly_commit,
            q_l: q_l_poly_commit,
            q_r: q_r_poly_commit,
            q_o: q_o_poly_commit,
            q_4: q_4_poly_commit,
            q_c: q_c_poly_commit,
            q_arith: q_arith_poly_commit,
        };

        // verifier Key for range circuits
        let range_verifier_key = widget::range::VerifierKey {
            q_range: q_range_poly_commit,
        };

        // verifier Key for logic circuits
        let logic_verifier_key = widget::logic::VerifierKey {
            q_c: q_c_poly_commit,
            q_logic: q_logic_poly_commit,
        };

        // verifier Key for ecc circuits
        let ecc_verifier_key =
            widget::ecc::scalar_mul::fixed_base::VerifierKey {
                q_l: q_l_poly_commit,
                q_r: q_r_poly_commit,
                q_fixed_group_add: q_fixed_group_add_poly_commit,
            };

        // verifier Key for curve addition circuits
        let curve_addition_verifier_key =
            widget::ecc::curve_addition::VerifierKey {
                q_variable_group_add: q_variable_group_add_poly_commit,
            };

        // verifier Key for permutation argument
        let permutation_verifier_key = widget::permutation::VerifierKey {
            s_sigma_1: s_sigma_1_poly_commit,
            s_sigma_2: s_sigma_2_poly_commit,
            s_sigma_3: s_sigma_3_poly_commit,
            s_sigma_4: s_sigma_4_poly_commit,
        };

        let verifier_key = widget::VerifierKey {
            n: constraints,
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
            q_4: q_4_poly,
            q_c: q_c_poly,
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

        let linear_eval_8n = Evaluations::from_vec_and_domain(
            domain_8n.coset_fft(&[BlsScalar::zero(), BlsScalar::one()]),
            domain_8n,
        );

        let arithmetic_prover_key = widget::arithmetic::ProverKey {
            q_m: (selectors.q_m, q_m_eval_8n),
            q_l: (selectors.q_l.clone(), q_l_eval_8n.clone()),
            q_r: (selectors.q_r.clone(), q_r_eval_8n.clone()),
            q_o: (selectors.q_o, q_o_eval_8n),
            q_4: (selectors.q_4, q_4_eval_8n),
            q_c: (selectors.q_c.clone(), q_c_eval_8n.clone()),
            q_arith: (selectors.q_arith, q_arith_eval_8n),
        };

        let range_prover_key = widget::range::ProverKey {
            q_range: (selectors.q_range, q_range_eval_8n),
        };

        let logic_prover_key = widget::logic::ProverKey {
            q_c: (selectors.q_c.clone(), q_c_eval_8n.clone()),
            q_logic: (selectors.q_logic, q_logic_eval_8n),
        };

        let ecc_prover_key = widget::ecc::scalar_mul::fixed_base::ProverKey {
            q_l: (selectors.q_l, q_l_eval_8n),
            q_r: (selectors.q_r, q_r_eval_8n),
            q_c: (selectors.q_c, q_c_eval_8n),
            q_fixed_group_add: (
                selectors.q_fixed_group_add,
                q_fixed_group_add_eval_8n,
            ),
        };

        let permutation_prover_key = widget::permutation::ProverKey {
            s_sigma_1: (selectors.s_sigma_1, s_sigma_1_eval_8n),
            s_sigma_2: (selectors.s_sigma_2, s_sigma_2_eval_8n),
            s_sigma_3: (selectors.s_sigma_3, s_sigma_3_eval_8n),
            s_sigma_4: (selectors.s_sigma_4, s_sigma_4_eval_8n),
            linear_evaluations: linear_eval_8n,
        };

        let curve_addition_prover_key =
            widget::ecc::curve_addition::ProverKey {
                q_variable_group_add: (
                    selectors.q_variable_group_add,
                    q_variable_group_add_eval_8n,
                ),
            };

        let v_h_coset_8n =
            domain_8n.compute_vanishing_poly_over_coset(domain.size() as u64);

        let prover_key = ProverKey {
            n: domain.size(),
            arithmetic: arithmetic_prover_key,
            logic: logic_prover_key,
            range: range_prover_key,
            permutation: permutation_prover_key,
            variable_base: curve_addition_prover_key,
            fixed_base: ecc_prover_key,
            v_h_coset_8n,
        };

        let public_input_indexes = prover.public_input_indexes();

        let label = label.to_vec();

        let prover = Prover::new(
            label.clone(),
            prover_key,
            commit_key,
            verifier_key,
            size,
            constraints,
        );

        let verifier = Verifier::new(
            label,
            verifier_key,
            opening_key,
            public_input_indexes,
            size,
            constraints,
        );

        Ok((prover, verifier))
    }
}
