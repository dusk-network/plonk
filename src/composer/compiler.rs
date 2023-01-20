// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use zero_bls12_381::Fr as BlsScalar;
use zero_kzg::{Fft, Polynomial};

use super::{Builder, Circuit, Composer, Prover, Verifier};
use crate::commitment_scheme::{CommitKey, OpeningKey, PublicParameters};
use crate::error::Error;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial as FftPolynomial};
use crate::proof_system::preprocess::Polynomials;
use crate::proof_system::{widget, ProverKey};
use sp_std::vec;

/// Generate the arguments to prove and verify a circuit
pub struct Compiler;

impl Compiler {
    /// Create a new arguments set from a given circuit instance
    ///
    /// Use the default implementation of the circuit
    pub fn compile<C>(
        pp: &PublicParameters,
        label: &[u8],
    ) -> Result<(Prover<C>, Verifier<C>), Error>
    where
        C: Circuit,
    {
        Self::compile_with_circuit(pp, label, &Default::default())
    }

    /// Create a new arguments set from a given circuit instance
    ///
    /// Use the provided circuit instead of the default implementation
    pub fn compile_with_circuit<C>(
        pp: &PublicParameters,
        label: &[u8],
        circuit: &C,
    ) -> Result<(Prover<C>, Verifier<C>), Error>
    where
        C: Circuit,
    {
        let max_size = (pp.commit_key.powers_of_g.len() - 1) >> 1;
        let mut prover = Builder::initialized(max_size);

        circuit.circuit(&mut prover)?;

        let n = (prover.constraints() + 6).next_power_of_two();

        let (commit, opening) = pp.trim(n)?;

        let (prover, verifier) =
            Self::preprocess(label, commit, opening, &prover)?;

        Ok((prover, verifier))
    }

    fn preprocess<C>(
        label: &[u8],
        commit_key: CommitKey,
        opening_key: OpeningKey,
        prover: &Builder,
    ) -> Result<(Prover<C>, Verifier<C>), Error>
    where
        C: Circuit,
    {
        let mut perm = prover.perm.clone();

        let constraints = prover.constraints();
        let size = constraints.next_power_of_two();
        let k = size.trailing_zeros();
        let fft = Fft::<BlsScalar>::new(k as usize);

        // 1. pad circuit to a power of two
        //
        // we use allocated vectors because the current ifft api only accepts
        // slices
        let mut q_m = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_l = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_r = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_o = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_c = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_d = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_arith = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_range = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_logic = Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_fixed_group_add =
            Polynomial::new(vec![BlsScalar::zero(); size]);
        let mut q_variable_group_add =
            Polynomial::new(vec![BlsScalar::zero(); size]);

        prover.constraints.iter().enumerate().for_each(|(i, c)| {
            q_m.0[i] = c.q_m;
            q_l.0[i] = c.q_l;
            q_r.0[i] = c.q_r;
            q_o.0[i] = c.q_o;
            q_c.0[i] = c.q_c;
            q_d.0[i] = c.q_d;
            q_arith.0[i] = c.q_arith;
            q_range.0[i] = c.q_range;
            q_logic.0[i] = c.q_logic;
            q_fixed_group_add.0[i] = c.q_fixed_group_add;
            q_variable_group_add.0[i] = c.q_variable_group_add;
        });

        fft.idft(&mut q_m);
        fft.idft(&mut q_l);
        fft.idft(&mut q_r);
        fft.idft(&mut q_o);
        fft.idft(&mut q_c);
        fft.idft(&mut q_d);
        fft.idft(&mut q_arith);
        fft.idft(&mut q_range);
        fft.idft(&mut q_logic);
        fft.idft(&mut q_fixed_group_add);
        fft.idft(&mut q_variable_group_add);

        let q_m_poly = FftPolynomial::from_coefficients_vec(q_m.0.clone());
        let q_l_poly = FftPolynomial::from_coefficients_vec(q_l.0.clone());
        let q_r_poly = FftPolynomial::from_coefficients_vec(q_r.0.clone());
        let q_o_poly = FftPolynomial::from_coefficients_vec(q_o.0.clone());
        let q_c_poly = FftPolynomial::from_coefficients_vec(q_c.0.clone());
        let q_d_poly = FftPolynomial::from_coefficients_vec(q_d.0.clone());
        let q_arith_poly =
            FftPolynomial::from_coefficients_vec(q_arith.0.clone());
        let q_range_poly =
            FftPolynomial::from_coefficients_vec(q_range.0.clone());
        let q_logic_poly =
            FftPolynomial::from_coefficients_vec(q_logic.0.clone());
        let q_fixed_group_add_poly =
            FftPolynomial::from_coefficients_vec(q_fixed_group_add.0.clone());
        let q_variable_group_add_poly = FftPolynomial::from_coefficients_vec(
            q_variable_group_add.0.clone(),
        );

        // 2. compute the sigma polynomials
        let [s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly] =
            perm.compute_sigma_polynomials(size, &fft);

        let q_m_poly_commit = commit_key.commit(&q_m_poly).unwrap_or_default();
        let q_l_poly_commit = commit_key.commit(&q_l_poly).unwrap_or_default();
        let q_r_poly_commit = commit_key.commit(&q_r_poly).unwrap_or_default();
        let q_o_poly_commit = commit_key.commit(&q_o_poly).unwrap_or_default();
        let q_c_poly_commit = commit_key.commit(&q_c_poly).unwrap_or_default();
        let q_d_poly_commit = commit_key.commit(&q_d_poly).unwrap_or_default();
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

        let s_sigma_1_poly_commit =
            FftPolynomial::from_coefficients_vec(s_sigma_1_poly.0.clone());
        let s_sigma_2_poly_commit =
            FftPolynomial::from_coefficients_vec(s_sigma_2_poly.0.clone());
        let s_sigma_3_poly_commit =
            FftPolynomial::from_coefficients_vec(s_sigma_3_poly.0.clone());
        let s_sigma_4_poly_commit =
            FftPolynomial::from_coefficients_vec(s_sigma_4_poly.0.clone());

        let s_sigma_1_poly_commit =
            commit_key.commit(&s_sigma_1_poly_commit)?;
        let s_sigma_2_poly_commit =
            commit_key.commit(&s_sigma_2_poly_commit)?;
        let s_sigma_3_poly_commit =
            commit_key.commit(&s_sigma_3_poly_commit)?;
        let s_sigma_4_poly_commit =
            commit_key.commit(&s_sigma_4_poly_commit)?;

        // verifier Key for arithmetic circuits
        let arithmetic_verifier_key = widget::arithmetic::VerifierKey {
            q_m: q_m_poly_commit,
            q_l: q_l_poly_commit,
            q_r: q_r_poly_commit,
            q_o: q_o_poly_commit,
            q_c: q_c_poly_commit,
            q_4: q_d_poly_commit,
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

        // The polynomial needs an evaluation domain of 4n.
        // Plus, adding the blinding factors translates to
        // the polynomial not fitting in 4n, so now we need
        // 8n, the next power of 2
        let n = (8 * fft.size()).next_power_of_two();
        let k = n.trailing_zeros();
        let fft_8n = Fft::new(k as usize);
        let domain_8n = EvaluationDomain::new(8 * fft.size())?;
        let mut s_sigma_1 = s_sigma_1_poly.clone();
        let mut s_sigma_2 = s_sigma_2_poly.clone();
        let mut s_sigma_3 = s_sigma_3_poly.clone();
        let mut s_sigma_4 = s_sigma_4_poly.clone();
        let mut min_p =
            Polynomial::new(vec![BlsScalar::zero(), BlsScalar::one()]);

        fft_8n.coset_dft(&mut q_m);
        fft_8n.coset_dft(&mut q_l);
        fft_8n.coset_dft(&mut q_r);
        fft_8n.coset_dft(&mut q_o);
        fft_8n.coset_dft(&mut q_c);
        fft_8n.coset_dft(&mut q_d);
        fft_8n.coset_dft(&mut q_arith);
        fft_8n.coset_dft(&mut q_range);
        fft_8n.coset_dft(&mut q_logic);
        fft_8n.coset_dft(&mut q_fixed_group_add);
        fft_8n.coset_dft(&mut q_variable_group_add);
        fft_8n.coset_dft(&mut s_sigma_1);
        fft_8n.coset_dft(&mut s_sigma_2);
        fft_8n.coset_dft(&mut s_sigma_3);
        fft_8n.coset_dft(&mut s_sigma_4);
        fft_8n.coset_dft(&mut min_p);

        let q_m_eval_8n =
            Evaluations::from_vec_and_domain(q_m.0.clone(), domain_8n);
        let q_l_eval_8n =
            Evaluations::from_vec_and_domain(q_l.0.clone(), domain_8n);
        let q_r_eval_8n =
            Evaluations::from_vec_and_domain(q_r.0.clone(), domain_8n);
        let q_o_eval_8n =
            Evaluations::from_vec_and_domain(q_o.0.clone(), domain_8n);
        let q_c_eval_8n =
            Evaluations::from_vec_and_domain(q_c.0.clone(), domain_8n);
        let q_4_eval_8n =
            Evaluations::from_vec_and_domain(q_d.0.clone(), domain_8n);
        let q_arith_eval_8n =
            Evaluations::from_vec_and_domain(q_arith.0.clone(), domain_8n);
        let q_range_eval_8n =
            Evaluations::from_vec_and_domain(q_range.0.clone(), domain_8n);
        let q_logic_eval_8n =
            Evaluations::from_vec_and_domain(q_logic.0.clone(), domain_8n);
        let q_fixed_group_add_eval_8n = Evaluations::from_vec_and_domain(
            q_fixed_group_add.0.clone(),
            domain_8n,
        );
        let q_variable_group_add_eval_8n = Evaluations::from_vec_and_domain(
            q_variable_group_add.0.clone(),
            domain_8n,
        );

        let s_sigma_1_eval_8n =
            Evaluations::from_vec_and_domain(s_sigma_1.0, domain_8n);
        let s_sigma_2_eval_8n =
            Evaluations::from_vec_and_domain(s_sigma_2.0, domain_8n);
        let s_sigma_3_eval_8n =
            Evaluations::from_vec_and_domain(s_sigma_3.0, domain_8n);
        let s_sigma_4_eval_8n =
            Evaluations::from_vec_and_domain(s_sigma_4.0, domain_8n);

        let linear_eval_8n =
            Evaluations::from_vec_and_domain(min_p.0, domain_8n);

        let s_sigma_1_poly =
            FftPolynomial::from_coefficients_vec(s_sigma_1_poly.0);
        let s_sigma_2_poly =
            FftPolynomial::from_coefficients_vec(s_sigma_2_poly.0);
        let s_sigma_3_poly =
            FftPolynomial::from_coefficients_vec(s_sigma_3_poly.0);
        let s_sigma_4_poly =
            FftPolynomial::from_coefficients_vec(s_sigma_4_poly.0);

        let selectors = Polynomials {
            q_m: q_m_poly,
            q_l: q_l_poly,
            q_r: q_r_poly,
            q_o: q_o_poly,
            q_c: q_c_poly,
            q_4: q_d_poly,
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

        let arithmetic_prover_key = widget::arithmetic::ProverKey {
            q_m: (selectors.q_m, q_m_eval_8n),
            q_l: (selectors.q_l.clone(), q_l_eval_8n.clone()),
            q_r: (selectors.q_r.clone(), q_r_eval_8n.clone()),
            q_o: (selectors.q_o, q_o_eval_8n),
            q_c: (selectors.q_c.clone(), q_c_eval_8n.clone()),
            q_4: (selectors.q_4, q_4_eval_8n),
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
            domain_8n.compute_vanishing_poly_over_coset(fft.size() as u64);

        let prover_key = ProverKey {
            n: fft.size(),
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
            verifier_key.clone(),
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
