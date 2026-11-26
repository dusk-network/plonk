// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
#[cfg(feature = "std")]
use rayon::prelude::*;

use crate::error::Error;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::proof_system::ProverKey;
use crate::proof_system::widget::ecc::curve_addition::proverkey::CurveAddChallenges;
use crate::proof_system::widget::ecc::scalar_mul::fixed_base::proverkey::FixedBaseChallenges;
use crate::proof_system::widget::logic::proverkey::LogicChallenges;
use crate::proof_system::widget::permutation::proverkey::PermutationChallenges;
use crate::proof_system::widget::range::proverkey::RangeChallenges;
use crate::util::batch_inversion_with_scratch;

const QUOTIENT_EVAL_CHUNK_SIZE: usize = 512;

/// Computes the Quotient [`Polynomial`] given the [`EvaluationDomain`], a
/// [`ProverKey`] and some other info.
pub(crate) fn compute(
    quotient_domain: &EvaluationDomain,
    prover_key: &ProverKey,
    z_poly: &Polynomial,
    (a_poly, b_poly, c_poly, d_poly): (
        &Polynomial,
        &Polynomial,
        &Polynomial,
        &Polynomial,
    ),
    public_inputs_poly: &Polynomial,
    vanishing_coset_inverses: &[BlsScalar; 8],
    (
        alpha,
        beta,
        gamma,
        range_challenge,
        logic_challenge,
        fixed_base_challenge,
        var_base_challenge,
    ): &(
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
    ),
) -> Result<Polynomial, Error> {
    let fft_roots = quotient_domain.precompute_fft_roots();
    let (
        [
            mut z_eval_8n,
            mut a_eval_8n,
            mut b_eval_8n,
            c_eval_8n,
            mut d_eval_8n,
        ],
        public_eval_8n,
    ) = compute_coset_evaluations(
        quotient_domain,
        &fft_roots,
        [z_poly, a_poly, b_poly, c_poly, d_poly],
        (!public_inputs_poly.is_zero()).then_some(public_inputs_poly),
    );
    drop(fft_roots);

    for i in 0..8 {
        z_eval_8n.push(z_eval_8n[i]);
        a_eval_8n.push(a_eval_8n[i]);
        b_eval_8n.push(b_eval_8n[i]);
        // c_eval_8n push not required
        d_eval_8n.push(d_eval_8n[i]);
    }

    let range_challenges = RangeChallenges::new(range_challenge);
    let logic_challenges = LogicChallenges::new(logic_challenge);
    let fixed_challenges = FixedBaseChallenges::new(fixed_base_challenge);
    let var_challenges = CurveAddChallenges::new(var_base_challenge);
    let perm_challenges = PermutationChallenges::new(alpha, beta, gamma);

    // The quotient domain has size 8n, while L1 is defined over the n-sized
    // proving domain: L1(x) = (x^n - 1) / (n * (x - 1)).
    let proving_domain_size_inv =
        quotient_domain.size_inv * BlsScalar::from(8u64);
    let l1_alpha_sq_scale = proving_domain_size_inv * alpha.square();

    let linear_evals = &prover_key.permutation.linear_evaluations.evals;
    let v_h_evals = &prover_key.v_h_coset_8n().evals;
    let public_eval_slice = public_eval_8n.as_deref();

    let domain_size = quotient_domain.size();
    let mut quotient = vec![BlsScalar::zero(); domain_size];

    let process_chunk = |chunk_idx: usize,
                         out_chunk: &mut [BlsScalar],
                         denom: &mut Vec<BlsScalar>,
                         prod: &mut Vec<BlsScalar>| {
        let start = chunk_idx * QUOTIENT_EVAL_CHUNK_SIZE;
        let len = out_chunk.len();

        denom.clear();
        denom.extend(
            linear_evals[start..start + len]
                .iter()
                .map(|evaluation| *evaluation - BlsScalar::one()),
        );
        batch_inversion_with_scratch(denom, prod);

        for (offset, (slot, denom_inv)) in
            out_chunk.iter_mut().zip(denom.iter()).enumerate()
        {
            let i = start + offset;
            let a = &a_eval_8n[i];
            let b = &b_eval_8n[i];
            let c = &c_eval_8n[i];
            let d = &d_eval_8n[i];
            let a_w = &a_eval_8n[i + 8];
            let b_w = &b_eval_8n[i + 8];
            let d_w = &d_eval_8n[i + 8];

            let t_arith =
                prover_key.arithmetic.compute_quotient_i(i, a, b, c, d);
            let t_range = prover_key.range.compute_quotient_i_with_challenges(
                i,
                &range_challenges,
                a,
                b,
                c,
                d,
                d_w,
            );
            let t_logic = prover_key.logic.compute_quotient_i_with_challenges(
                i,
                &logic_challenges,
                a,
                a_w,
                b,
                b_w,
                c,
                d,
                d_w,
            );
            let t_fixed =
                prover_key.fixed_base.compute_quotient_i_with_challenges(
                    i,
                    &fixed_challenges,
                    a,
                    a_w,
                    b,
                    b_w,
                    c,
                    d,
                    d_w,
                );
            let t_var =
                prover_key.variable_base.compute_quotient_i_with_challenges(
                    i,
                    &var_challenges,
                    a,
                    a_w,
                    b,
                    b_w,
                    c,
                    d,
                    d_w,
                );

            let mut t_1 = t_arith + t_range + t_logic + t_fixed + t_var;
            if let Some(pi_evals) = public_eval_slice {
                t_1 += &pi_evals[i];
            }

            let l1_alpha_sq = *denom_inv * v_h_evals[i] * l1_alpha_sq_scale;
            let t_2 =
                prover_key.permutation.compute_quotient_i_with_challenges(
                    i,
                    a,
                    b,
                    c,
                    d,
                    &z_eval_8n[i],
                    &z_eval_8n[i + 8],
                    &l1_alpha_sq,
                    &perm_challenges,
                );

            *slot = (t_1 + t_2) * vanishing_coset_inverses[i & 7];
        }
    };

    let scratch_cap = domain_size.min(QUOTIENT_EVAL_CHUNK_SIZE);

    #[cfg(feature = "std")]
    quotient
        .par_chunks_mut(QUOTIENT_EVAL_CHUNK_SIZE)
        .enumerate()
        .for_each_init(
            || {
                (
                    Vec::with_capacity(scratch_cap),
                    Vec::with_capacity(scratch_cap),
                )
            },
            |(denom, prod), (chunk_idx, out_chunk)| {
                process_chunk(chunk_idx, out_chunk, denom, prod);
            },
        );

    #[cfg(not(feature = "std"))]
    {
        let mut denom = Vec::with_capacity(scratch_cap);
        let mut prod = Vec::with_capacity(scratch_cap);
        for (chunk_idx, out_chunk) in
            quotient.chunks_mut(QUOTIENT_EVAL_CHUNK_SIZE).enumerate()
        {
            process_chunk(chunk_idx, out_chunk, &mut denom, &mut prod);
        }
    }

    drop((
        z_eval_8n,
        a_eval_8n,
        b_eval_8n,
        c_eval_8n,
        d_eval_8n,
        public_eval_8n,
    ));

    quotient_domain.coset_ifft_in_place(&mut quotient);
    let quotient_poly = Polynomial::from_coefficients_vec(quotient);

    // A satisfied assignment yields a numerator divisible by the vanishing
    // polynomial of the domain, and the quotient's degree is bounded by the
    // numerator's: the permutation product z(x) (degree n + 2, with hiding
    // degree 2) times the four wire factors (degree n + 2 for a, b and d,
    // and n + 1 for c) has degree 5n + 9, and every gate identity stays below
    // that. Dividing by the vanishing polynomial leaves at most 4n + 9.
    //
    // An unsatisfied assignment leaves a nonzero remainder r(x) with
    // deg r < n. On the 8n-sized coset the pointwise division then computes
    // q(x) + r(x)/z_H(x), and 1/z_H interpolates over that coset to
    // c_0 + c_1·x^n + ... + c_7·x^7n with c_7 nonzero (z_H only takes 8
    // distinct values there), pushing the interpolated result to a degree of
    // at least 7n. The check is anchored on that detection floor rather than
    // the honest ceiling, so it stays correct should blinding or a new gate
    // ever push the honest quotient past 4n + 9 — strictly below 7n.
    // Unsatisfied assignments are caught even when the commit key is roomy
    // enough (small circuits, deserialized oversized keys) that the split
    // quotient chunks would have committed fine and only failed at
    // verification.
    //
    // `from_coefficients_vec` trims trailing zero coefficients, so the
    // coefficient vector is either empty or ends on a non-zero coefficient
    // and `len() == degree + 1`. Comparing lengths therefore reads the
    // degree in constant time instead of rescanning the coefficients, and
    // `degree() >= 7n` becomes `len() > 7n` (the empty polynomial passes
    // either way).
    if quotient_poly.len() > 7 * (quotient_domain.size() / 8) {
        return Err(Error::CircuitUnsatisfied);
    }

    Ok(quotient_poly)
}

fn compute_coset_evaluations(
    domain: &EvaluationDomain,
    fft_roots: &[BlsScalar],
    polynomials: [&Polynomial; 5],
    public_inputs_poly: Option<&Polynomial>,
) -> ([Vec<BlsScalar>; 5], Option<Vec<BlsScalar>>) {
    #[cfg(not(feature = "std"))]
    {
        let evaluations = polynomials
            .map(|poly| domain.coset_fft_with_roots(poly, fft_roots));
        let public_evals = public_inputs_poly
            .map(|poly| domain.coset_fft_with_roots(poly, fft_roots));
        (evaluations, public_evals)
    }

    #[cfg(feature = "std")]
    {
        if let Some(pi_poly) = public_inputs_poly {
            let all_polys = [
                polynomials[0],
                polynomials[1],
                polynomials[2],
                polynomials[3],
                polynomials[4],
                pi_poly,
            ];
            let mut evaluations: [Vec<BlsScalar>; 6] = Default::default();
            evaluations.par_iter_mut().zip(&all_polys[..]).for_each(
                |(slot, poly)| {
                    *slot = domain.coset_fft_with_roots(poly, fft_roots)
                },
            );
            let [z, a, b, c, d, pi] = evaluations;
            ([z, a, b, c, d], Some(pi))
        } else {
            let mut evaluations: [Vec<BlsScalar>; 5] = Default::default();
            evaluations.par_iter_mut().zip(&polynomials[..]).for_each(
                |(slot, poly)| {
                    *slot = domain.coset_fft_with_roots(poly, fft_roots)
                },
            );
            (evaluations, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn coset_evaluations_preserve_input_order_across_nested_rayon_pools() {
        let domain = EvaluationDomain::new(1 << 12).unwrap();
        let polynomials = core::array::from_fn(|index| {
            Polynomial::from_coefficients_vec(
                (0..domain.size())
                    .map(|coefficient| {
                        BlsScalar::from(
                            (index * domain.size() + coefficient + 1) as u64,
                        )
                    })
                    .collect(),
            )
        });
        let pi_poly = Polynomial::from_coefficients_vec(
            (0..domain.size())
                .map(|c| BlsScalar::from((c + 99) as u64))
                .collect(),
        );
        let reference_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let expected = reference_pool.install(|| {
            polynomials.each_ref().map(|poly| domain.coset_fft(poly))
        });
        let expected_pi = reference_pool.install(|| domain.coset_fft(&pi_poly));

        for threads in [8, 9] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let (actual, actual_none) = pool.install(|| {
                let roots = domain.precompute_fft_roots();
                compute_coset_evaluations(
                    &domain,
                    &roots,
                    polynomials.each_ref(),
                    None,
                )
            });
            assert_eq!(
                actual, expected,
                "failed (no pi) with {threads} threads"
            );
            assert!(actual_none.is_none());

            let (actual_6, actual_pi) = pool.install(|| {
                let roots = domain.precompute_fft_roots();
                compute_coset_evaluations(
                    &domain,
                    &roots,
                    polynomials.each_ref(),
                    Some(&pi_poly),
                )
            });
            assert_eq!(
                actual_6, expected,
                "failed (with pi) with {threads} threads"
            );
            assert_eq!(
                actual_pi.as_deref(),
                Some(expected_pi.as_slice()),
                "pi failed with {threads} threads"
            );
        }
    }

    #[test]
    fn quotient_poly_handles_small_large_pi_threads_and_unsatisfied() {
        use dusk_jubjub::{JubJubExtended, JubJubScalar};
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        use crate::prelude::{
            Circuit, Compiler, Composer, Constraint, PublicParameters,
            TorsionFreeWitnessPoint,
        };

        struct AllWidgetsCircuit {
            repeat: usize,
            public_value: Option<BlsScalar>,
        }

        impl Circuit for AllWidgetsCircuit {
            fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
                let a = composer.append_witness(BlsScalar::from(2u64));
                let b = composer.append_witness(BlsScalar::from(3u64));
                let y = composer.append_witness(JubJubScalar::from(5u64));
                let z = composer.append_point(
                    JubJubExtended::from(dusk_jubjub::GENERATOR_EXTENDED)
                        * JubJubScalar::from(5u64),
                )?;
                let tf_z = TorsionFreeWitnessPoint::new_unchecked(z);

                if let Some(pi) = self.public_value {
                    composer.append_public(pi);
                }
                for _ in 0..self.repeat {
                    let prod =
                        composer.gate_mul(Constraint::new().mult(1).a(a).b(b));
                    composer.assert_equal_constant(
                        prod,
                        BlsScalar::from(6u64),
                        None,
                    );
                    if self.repeat > 1 {
                        composer.component_range_bits::<8>(a);
                        composer.append_logic_xor::<8>(a, b);
                        composer.component_add_point(tf_z, tf_z);
                        composer.component_mul_generator(
                            y,
                            dusk_jubjub::GENERATOR_EXTENDED,
                        )?;
                    }
                }
                Ok(())
            }
        }

        let mut setup_rng = StdRng::seed_from_u64(0x7777);
        let pp = PublicParameters::setup(1 << 11, &mut setup_rng).unwrap();

        // Cover both `8n < QUOTIENT_EVAL_CHUNK_SIZE` and
        // `8n > QUOTIENT_EVAL_CHUNK_SIZE`, with no PI, zero PI, and nonzero PI.
        let configs = [
            (1usize, None),
            (1, Some(BlsScalar::zero())),
            (1, Some(BlsScalar::from(42u64))),
            (2, None),
            (2, Some(BlsScalar::from(99u64))),
        ];

        for (repeat, public_value) in configs {
            let circuit = AllWidgetsCircuit {
                repeat,
                public_value,
            };
            let (prover, verifier) =
                Compiler::compile_with_circuit(&pp, b"quot-eq", &circuit)
                    .unwrap();

            if repeat == 1 {
                assert!(
                    prover.prover_key.v_h_coset_8n().evals.len()
                        < QUOTIENT_EVAL_CHUNK_SIZE
                );
            } else {
                assert!(
                    prover.prover_key.v_h_coset_8n().evals.len()
                        > QUOTIENT_EVAL_CHUNK_SIZE
                );
            }

            let mut rng = StdRng::seed_from_u64(0x8888);
            let (proof, public_inputs) =
                prover.prove(&mut rng, &circuit).unwrap();
            verifier.verify(&proof, &public_inputs).unwrap();

            let domain = EvaluationDomain::new(prover.size).unwrap();
            let q_domain = EvaluationDomain::new(8 * prover.size).unwrap();
            let mut v_inv = [BlsScalar::zero(); 8];
            v_inv.copy_from_slice(&prover.prover_key.v_h_coset_8n().evals[..8]);
            crate::util::batch_inversion(&mut v_inv);

            let comp = Composer::prove(prover.constraints, &circuit).unwrap();
            let mut a_s = vec![BlsScalar::zero(); prover.size];
            let mut b_s = vec![BlsScalar::zero(); prover.size];
            let mut c_s = vec![BlsScalar::zero(); prover.size];
            let mut d_s = vec![BlsScalar::zero(); prover.size];
            for (i, gate) in comp.constraints.iter().enumerate() {
                a_s[i] = comp[gate.a];
                b_s[i] = comp[gate.b];
                c_s[i] = comp[gate.c];
                d_s[i] = comp[gate.d];
            }
            let a_poly = Polynomial::from_coefficients_vec(domain.ifft(&a_s));
            let b_poly = Polynomial::from_coefficients_vec(domain.ifft(&b_s));
            let c_poly = Polynomial::from_coefficients_vec(domain.ifft(&c_s));
            let d_poly = Polynomial::from_coefficients_vec(domain.ifft(&d_s));

            let sigma = [
                domain.fft(&prover.prover_key.permutation.s_sigma_1.0),
                domain.fft(&prover.prover_key.permutation.s_sigma_2.0),
                domain.fft(&prover.prover_key.permutation.s_sigma_3.0),
                domain.fft(&prover.prover_key.permutation.s_sigma_4.0),
            ];
            let beta = BlsScalar::from(11u64);
            let gamma = BlsScalar::from(13u64);
            let perm = comp.perm.compute_permutation_vec(
                &domain,
                [&a_s, &b_s, &c_s, &d_s],
                &beta,
                &gamma,
                [&sigma[0], &sigma[1], &sigma[2], &sigma[3]],
            );
            let z_poly = Polynomial::from_coefficients_vec(domain.ifft(&perm));
            let pi_poly = match public_value {
                Some(v) if v != BlsScalar::zero() => {
                    let idxs = comp.public_input_indexes();
                    let dense =
                        Composer::dense_public_inputs(&idxs, &[v], prover.size);
                    Polynomial::from_coefficients_vec(domain.ifft(&dense))
                }
                _ => Polynomial::zero(),
            };
            let challenges = (
                BlsScalar::from(17u64),
                beta,
                gamma,
                BlsScalar::from(19u64),
                BlsScalar::from(23u64),
                BlsScalar::from(29u64),
                BlsScalar::from(31u64),
            );

            let baseline = compute(
                &q_domain,
                &prover.prover_key,
                &z_poly,
                (&a_poly, &b_poly, &c_poly, &d_poly),
                &pi_poly,
                &v_inv,
                &challenges,
            )
            .unwrap();

            #[cfg(feature = "std")]
            for threads in [1, 3, 4, 8, 9] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap();
                let par_actual = pool.install(|| {
                    compute(
                        &q_domain,
                        &prover.prover_key,
                        &z_poly,
                        (&a_poly, &b_poly, &c_poly, &d_poly),
                        &pi_poly,
                        &v_inv,
                        &challenges,
                    )
                    .unwrap()
                });
                assert_eq!(par_actual, baseline);
            }

            // Corrupt a wire polynomial so the circuit is unsatisfied and
            // confirm `Error::CircuitUnsatisfied` is returned.
            let mut bad_a = a_s.clone();
            bad_a[0] += BlsScalar::one();
            let bad_a_poly =
                Polynomial::from_coefficients_vec(domain.ifft(&bad_a));
            let err = compute(
                &q_domain,
                &prover.prover_key,
                &z_poly,
                (&bad_a_poly, &b_poly, &c_poly, &d_poly),
                &pi_poly,
                &v_inv,
                &challenges,
            );
            assert_eq!(err, Err(Error::CircuitUnsatisfied));
        }
    }
}
