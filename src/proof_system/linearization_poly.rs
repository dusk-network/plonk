// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Serialize,
    ser::{ScratchSpace, Serializer},
};

use crate::BufferWriter;
#[cfg(feature = "rkyv-impl")]
use crate::archive::{InvalidArchive, check_fields, unarchive};
#[cfg(feature = "alloc")]
use crate::{
    fft::{EvaluationDomain, Polynomial},
    proof_system::{ProverKey, proof},
};

/// Subset of all of the evaluations. These evaluations
/// are added to the [`Proof`](super::Proof).
#[derive(Debug, Eq, PartialEq, Clone, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace"))
)]
pub(crate) struct ProofEvaluations {
    // Evaluation of the witness polynomial for the left wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_eval: BlsScalar,
    // Evaluation of the witness polynomial for the right wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_eval: BlsScalar,
    // Evaluation of the witness polynomial for the output wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) c_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_w_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_w_eval: BlsScalar,
    // Evaluation of the witness polynomial for the fourth wire at `z * root of
    // unity`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_w_eval: BlsScalar,
    // Evaluation of the arithmetic selector polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_arith_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_c_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_l_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_r_eval: BlsScalar,
    //
    // Evaluation of the left sigma polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_1_eval: BlsScalar,
    // Evaluation of the right sigma polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_2_eval: BlsScalar,
    // Evaluation of the out sigma polynomial at `z`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_3_eval: BlsScalar,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of
    // unity`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) z_eval: BlsScalar,
}

#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinearizationChallenges {
    pub(crate) alpha: BlsScalar,
    pub(crate) beta: BlsScalar,
    pub(crate) gamma: BlsScalar,
    pub(crate) range_separation: BlsScalar,
    pub(crate) logic_separation: BlsScalar,
    pub(crate) fixed_base_separation: BlsScalar,
    pub(crate) variable_base_separation: BlsScalar,
    pub(crate) z: BlsScalar,
}

#[cfg(feature = "rkyv-impl")]
impl<C: ?Sized> CheckBytes<C> for ArchivedProofEvaluations {
    type Error = InvalidArchive;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        check_fields!(
            value,
            context,
            a_eval,
            b_eval,
            c_eval,
            d_eval,
            a_w_eval,
            b_w_eval,
            d_w_eval,
            q_arith_eval,
            q_c_eval,
            q_l_eval,
            q_r_eval,
            s_sigma_1_eval,
            s_sigma_2_eval,
            s_sigma_3_eval,
            z_eval,
        );
        // Decoding the byte encoding reduces non-canonical limbs, so it
        // changes the value.
        let archived = unsafe { &*value };
        let evaluations = unarchive::<ProofEvaluations>(archived);
        match ProofEvaluations::from_bytes(&evaluations.to_bytes()) {
            Ok(decoded) if decoded == evaluations => Ok(archived),
            _ => Err(InvalidArchive),
        }
    }
}

// The struct ProofEvaluations has 15 BlsScalars
impl Serializable<{ 15 * BlsScalar::SIZE }> for ProofEvaluations {
    type Error = dusk_bytes::Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        let mut writer = BufferWriter::new(&mut buf);
        writer.write(&self.a_eval.to_bytes());
        writer.write(&self.b_eval.to_bytes());
        writer.write(&self.c_eval.to_bytes());
        writer.write(&self.d_eval.to_bytes());
        writer.write(&self.a_w_eval.to_bytes());
        writer.write(&self.b_w_eval.to_bytes());
        writer.write(&self.d_w_eval.to_bytes());
        writer.write(&self.q_arith_eval.to_bytes());
        writer.write(&self.q_c_eval.to_bytes());
        writer.write(&self.q_l_eval.to_bytes());
        writer.write(&self.q_r_eval.to_bytes());
        writer.write(&self.s_sigma_1_eval.to_bytes());
        writer.write(&self.s_sigma_2_eval.to_bytes());
        writer.write(&self.s_sigma_3_eval.to_bytes());
        writer.write(&self.z_eval.to_bytes());
        writer.finish();

        buf
    }

    fn from_bytes(
        buf: &[u8; Self::SIZE],
    ) -> Result<ProofEvaluations, Self::Error> {
        let mut buffer = &buf[..];
        let a_eval = BlsScalar::from_reader(&mut buffer)?;
        let b_eval = BlsScalar::from_reader(&mut buffer)?;
        let c_eval = BlsScalar::from_reader(&mut buffer)?;
        let d_eval = BlsScalar::from_reader(&mut buffer)?;
        let a_w_eval = BlsScalar::from_reader(&mut buffer)?;
        let b_w_eval = BlsScalar::from_reader(&mut buffer)?;
        let d_w_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_arith_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_c_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_l_eval = BlsScalar::from_reader(&mut buffer)?;
        let q_r_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_1_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_2_eval = BlsScalar::from_reader(&mut buffer)?;
        let s_sigma_3_eval = BlsScalar::from_reader(&mut buffer)?;
        let z_eval = BlsScalar::from_reader(&mut buffer)?;

        Ok(ProofEvaluations {
            a_eval,
            b_eval,
            c_eval,
            d_eval,
            a_w_eval,
            b_w_eval,
            d_w_eval,
            q_arith_eval,
            q_c_eval,
            q_l_eval,
            q_r_eval,
            s_sigma_1_eval,
            s_sigma_2_eval,
            s_sigma_3_eval,
            z_eval,
        })
    }
}

/// Compute the linearization polynomial.
#[cfg(feature = "alloc")]
pub(crate) fn compute(
    prover_key: &ProverKey,
    challenges: &LinearizationChallenges,
    z_poly: &Polynomial,
    evaluations: &ProofEvaluations,
    domain: &EvaluationDomain,
    t_low_poly: &Polynomial,
    t_mid_poly: &Polynomial,
    t_high_poly: &Polynomial,
    t_fourth_poly: &Polynomial,
    pub_inputs: &[BlsScalar],
) -> Polynomial {
    use crate::proof_system::widget::ecc::curve_addition::ProverKey as CurveAddProverKey;
    use crate::proof_system::widget::ecc::scalar_mul::fixed_base::ProverKey as FixedBaseProverKey;
    use crate::proof_system::widget::logic::ProverKey as LogicProverKey;
    use crate::proof_system::widget::permutation::ProverKey as PermutationProverKey;
    use crate::proof_system::widget::range::ProverKey as RangeProverKey;

    let q_arith = evaluations.q_arith_eval;
    let arith_q_m = evaluations.a_eval * evaluations.b_eval * q_arith;
    let arith_q_l = evaluations.a_eval * q_arith;
    let arith_q_r = evaluations.b_eval * q_arith;
    let arith_q_o = evaluations.c_eval * q_arith;
    let arith_q_f = evaluations.d_eval * q_arith;

    let range_scalar = RangeProverKey::linearization_scalar(
        &challenges.range_separation,
        evaluations,
    );
    let logic_scalar = LogicProverKey::linearization_scalar(
        &challenges.logic_separation,
        evaluations,
    );
    let fixed_scalar = FixedBaseProverKey::linearization_scalar(
        &challenges.fixed_base_separation,
        evaluations,
    );
    let var_scalar = CurveAddProverKey::linearization_scalar(
        &challenges.variable_base_separation,
        evaluations,
    );

    // Pass `domain` explicitly rather than inferring `z_poly.degree() - 2`:
    // on a 4-row circuit when the linear and quadratic permutation blinders
    // are zero (and the constant blinder is nonzero), `z_poly` has degree 4,
    // so `z_poly.degree() - 2` evaluates `L_1` over a 2-element domain and
    // produces an invalid proof. Using the actual proving `domain` fixes that
    // edge case (an intentional bug-fix exception to strict byte-for-byte
    // proof compatibility with `master`).
    let (z_poly_scalar, s_sigma_4_scalar) =
        PermutationProverKey::linearization_scalars(
            domain,
            &challenges.z,
            (&challenges.alpha, &challenges.beta, &challenges.gamma),
            (
                &evaluations.a_eval,
                &evaluations.b_eval,
                &evaluations.c_eval,
                &evaluations.d_eval,
            ),
            (
                &evaluations.s_sigma_1_eval,
                &evaluations.s_sigma_2_eval,
                &evaluations.s_sigma_3_eval,
            ),
            &evaluations.z_eval,
        );

    let domain_size = domain.size() as u64;
    let z_n = challenges.z.pow(&[domain_size, 0, 0, 0]);
    let z_two_n = z_n.square();
    let z_three_n = z_two_n * z_n;

    let z_h_eval = -(z_n - BlsScalar::one());
    let t_low_scalar = z_h_eval;
    let t_mid_scalar = z_h_eval * z_n;
    let t_high_scalar = z_h_eval * z_two_n;
    let t_fourth_scalar = z_h_eval * z_three_n;

    let pi_eval = proof::alloc::compute_barycentric_eval(
        pub_inputs,
        &challenges.z,
        domain,
    );

    let terms: [(BlsScalar, &Polynomial); 16] = [
        (arith_q_m, &prover_key.arithmetic.q_m.0),
        (arith_q_l, &prover_key.arithmetic.q_l.0),
        (arith_q_r, &prover_key.arithmetic.q_r.0),
        (arith_q_o, &prover_key.arithmetic.q_o.0),
        (arith_q_f, &prover_key.arithmetic.q_f.0),
        (q_arith, &prover_key.arithmetic.q_c.0),
        (range_scalar, &prover_key.range.q_range.0),
        (logic_scalar, &prover_key.logic.q_logic.0),
        (fixed_scalar, &prover_key.fixed_base.q_fixed_group_add.0),
        (var_scalar, &prover_key.variable_base.q_variable_group_add.0),
        (z_poly_scalar, z_poly),
        (s_sigma_4_scalar, &prover_key.permutation.s_sigma_4.0),
        (t_low_scalar, t_low_poly),
        (t_mid_scalar, t_mid_poly),
        (t_high_scalar, t_high_poly),
        (t_fourth_scalar, t_fourth_poly),
    ];

    let max_len = terms
        .iter()
        .filter(|(scalar, poly)| {
            *scalar != BlsScalar::zero() && !poly.is_zero()
        })
        .map(|(_, poly)| poly.len())
        .max()
        .unwrap_or(0)
        .max(usize::from(pi_eval != BlsScalar::zero()));

    if max_len == 0 {
        return Polynomial::zero();
    }

    let mut coeffs = vec![BlsScalar::zero(); max_len];

    let accumulate_range = |start: usize, out_chunk: &mut [BlsScalar]| {
        for (scalar, poly) in &terms {
            if *scalar == BlsScalar::zero() || start >= poly.len() {
                continue;
            }
            let end = (start + out_chunk.len()).min(poly.len());
            for (dst, src) in
                out_chunk[..end - start].iter_mut().zip(&poly[start..end])
            {
                *dst += *src * scalar;
            }
        }
    };

    #[cfg(feature = "std")]
    {
        const PARALLEL_LIN_MIN_LEN: usize = 1 << 12;
        const LIN_CHUNK_SIZE: usize = 512;
        if max_len >= PARALLEL_LIN_MIN_LEN && rayon::current_num_threads() > 1 {
            use rayon::prelude::*;

            coeffs.par_chunks_mut(LIN_CHUNK_SIZE).enumerate().for_each(
                |(chunk_idx, out_chunk)| {
                    accumulate_range(chunk_idx * LIN_CHUNK_SIZE, out_chunk);
                },
            );
        } else {
            accumulate_range(0, &mut coeffs);
        }
    }

    #[cfg(not(feature = "std"))]
    accumulate_range(0, &mut coeffs);

    coeffs[0] += pi_eval;
    Polynomial::from_coefficients_vec(coeffs)
}

#[cfg(test)]
mod evaluations_tests {
    use super::*;

    #[test]
    fn proof_evaluations_dusk_bytes_serde() {
        let proof_evals = ProofEvaluations::default();
        let bytes = proof_evals.to_bytes();
        let obtained_evals = ProofEvaluations::from_slice(&bytes)
            .expect("Deserialization error");
        assert_eq!(proof_evals.to_bytes(), obtained_evals.to_bytes())
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn fused_linearization_matches_parallel_and_handles_unequal_lengths() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        use crate::error::Error;
        use crate::prelude::{
            Circuit, Compiler, Composer, Constraint, PublicParameters,
        };

        #[derive(Default)]
        struct LargeCircuit;

        impl Circuit for LargeCircuit {
            fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
                let a = composer.append_witness(BlsScalar::from(2u64));
                let b = composer.append_witness(BlsScalar::from(3u64));
                composer.append_public(BlsScalar::from(11u64));
                for _ in 0..4100 {
                    composer.gate_mul(Constraint::new().mult(1).a(a).b(b));
                }
                Ok(())
            }
        }

        let mut rng = StdRng::seed_from_u64(0x6161);
        let pp = PublicParameters::setup(1 << 13, &mut rng).unwrap();
        let (prover, _) =
            Compiler::compile::<LargeCircuit>(&pp, b"lin-par").unwrap();
        let domain = EvaluationDomain::new(prover.size).unwrap();
        assert!(domain.size() >= 4096);

        let poly_of = |len: usize, off: u64| {
            Polynomial::from_coefficients_vec(
                (0..len).map(|i| BlsScalar::from(i as u64 + off)).collect(),
            )
        };
        let z_poly = poly_of(domain.size() + 3, 1);
        let t_low = poly_of(domain.size() + 1, 2);
        let t_mid = Polynomial::zero();
        let t_high = poly_of(17, 4);
        let t_fourth = poly_of(domain.size() + 5, 5);
        let evaluations = ProofEvaluations {
            a_eval: BlsScalar::from(2),
            b_eval: BlsScalar::from(3),
            c_eval: BlsScalar::from(5),
            d_eval: BlsScalar::from(7),
            a_w_eval: BlsScalar::from(11),
            b_w_eval: BlsScalar::from(13),
            d_w_eval: BlsScalar::from(17),
            q_arith_eval: BlsScalar::from(19),
            q_c_eval: BlsScalar::from(23),
            q_l_eval: BlsScalar::from(29),
            q_r_eval: BlsScalar::from(31),
            s_sigma_1_eval: BlsScalar::from(37),
            s_sigma_2_eval: BlsScalar::from(41),
            s_sigma_3_eval: BlsScalar::from(43),
            z_eval: BlsScalar::from(47),
        };
        let challenges = LinearizationChallenges {
            alpha: BlsScalar::from(53),
            beta: BlsScalar::from(59),
            gamma: BlsScalar::from(61),
            range_separation: BlsScalar::from(67),
            logic_separation: BlsScalar::from(71),
            fixed_base_separation: BlsScalar::from(73),
            variable_base_separation: BlsScalar::from(79),
            z: BlsScalar::from(83),
        };
        let pub_inputs = [BlsScalar::from(11u64)];

        let baseline = compute(
            &prover.prover_key,
            &challenges,
            &z_poly,
            &evaluations,
            &domain,
            &t_low,
            &t_mid,
            &t_high,
            &t_fourth,
            &pub_inputs,
        );
        assert!(!baseline.is_zero());

        #[cfg(feature = "std")]
        for threads in [1, 3, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let actual = pool.install(|| {
                compute(
                    &prover.prover_key,
                    &challenges,
                    &z_poly,
                    &evaluations,
                    &domain,
                    &t_low,
                    &t_mid,
                    &t_high,
                    &t_fourth,
                    &pub_inputs,
                )
            });
            assert_eq!(actual, baseline);
        }
    }
}
