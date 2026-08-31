// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! In pairing-based SNARKs like GM17, we need to calculate
//! a quotient polynomial over a target polynomial with roots
//! at distinct points associated with each constraint of the
//! constraint system. In order to be efficient, we choose these
//! roots to be the powers of a 2^n root of unity in the field.
//! This allows us to perform polynomial operations in O(n)
//! by performing an O(n log n) FFT over such a domain.

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

/// Defines a domain over which finite field (I)FFTs can be performed. Works
/// only for fields that have a large multiplicative subgroup of size that is
/// a power-of-2.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct EvaluationDomain {
    /// The size of the domain.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) size: u64,
    /// `log_2(self.size)`.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) log_size_of_group: u32,
    /// Size of the domain as a field element.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) size_as_field_element: BlsScalar,
    /// Inverse of the size in the field.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) size_inv: BlsScalar,
    /// A generator of the subgroup.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) group_gen: BlsScalar,
    /// Inverse of the generator of the subgroup.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) group_gen_inv: BlsScalar,
    /// Multiplicative generator of the finite field.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) generator_inv: BlsScalar,
}

impl Serializable<{ u64::SIZE + u32::SIZE + 5 * BlsScalar::SIZE }>
    for EvaluationDomain
{
    type Error = dusk_bytes::Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        let mut writer = BufferWriter::new(&mut buf);
        writer.write(&self.size.to_bytes());
        writer.write(&self.log_size_of_group.to_bytes());
        writer.write(&self.size_as_field_element.to_bytes());
        writer.write(&self.size_inv.to_bytes());
        writer.write(&self.group_gen.to_bytes());
        writer.write(&self.group_gen_inv.to_bytes());
        writer.write(&self.generator_inv.to_bytes());
        writer.finish();

        buf
    }

    fn from_bytes(
        buf: &[u8; Self::SIZE],
    ) -> Result<EvaluationDomain, Self::Error> {
        let mut buffer = &buf[..];
        let size = u64::from_reader(&mut buffer)?;
        let log_size_of_group = u32::from_reader(&mut buffer)?;
        let size_as_field_element = BlsScalar::from_reader(&mut buffer)?;
        let size_inv = BlsScalar::from_reader(&mut buffer)?;
        let group_gen = BlsScalar::from_reader(&mut buffer)?;
        let group_gen_inv = BlsScalar::from_reader(&mut buffer)?;
        let generator_inv = BlsScalar::from_reader(&mut buffer)?;

        Ok(EvaluationDomain {
            size,
            log_size_of_group,
            size_as_field_element,
            size_inv,
            group_gen,
            group_gen_inv,
            generator_inv,
        })
    }
}

#[cfg(feature = "alloc")]
pub(crate) mod alloc {

    use super::*;
    use crate::error::Error;
    use crate::fft::Evaluations;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use core::ops::MulAssign;

    use dusk_bls12_381::{GENERATOR, ROOT_OF_UNITY, TWO_ADACITY};
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    impl EvaluationDomain {
        /// Construct a domain that is large enough for evaluations of a
        /// polynomial having `num_coeffs` coefficients.
        pub(crate) fn new(num_coeffs: usize) -> Result<Self, Error> {
            // Compute the size of our evaluation domain
            let size = num_coeffs.checked_next_power_of_two().ok_or(
                Error::InvalidEvalDomainSize {
                    log_size_of_group: usize::BITS,
                    adacity: TWO_ADACITY,
                },
            )? as u64;
            let log_size_of_group = size.trailing_zeros();

            if log_size_of_group >= TWO_ADACITY {
                return Err(Error::InvalidEvalDomainSize {
                    log_size_of_group,
                    adacity: TWO_ADACITY,
                });
            }

            // Compute the generator for the multiplicative subgroup.
            // It should be 2^(log_size_of_group) root of unity.

            let mut group_gen = ROOT_OF_UNITY;
            for _ in log_size_of_group..TWO_ADACITY {
                group_gen = group_gen.square();
            }
            let size_as_field_element = BlsScalar::from(size);
            let size_inv = size_as_field_element.invert().unwrap();

            Ok(EvaluationDomain {
                size,
                log_size_of_group,
                size_as_field_element,
                size_inv,
                group_gen,
                group_gen_inv: group_gen.invert().unwrap(),
                generator_inv: GENERATOR.invert().unwrap(),
            })
        }

        /// Return the size of `self`.
        pub(crate) fn size(&self) -> usize {
            self.size as usize
        }

        /// Compute a FFT.
        pub(crate) fn fft(&self, coeffs: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut coeffs = coeffs.to_vec();
            self.fft_in_place(&mut coeffs);
            coeffs
        }

        /// Compute a FFT, modifying the vector in place.
        fn fft_in_place(&self, coeffs: &mut Vec<BlsScalar>) {
            coeffs.resize(self.size(), BlsScalar::zero());
            best_fft(coeffs, self.group_gen, self.log_size_of_group)
        }

        /// Compute an IFFT.
        pub(crate) fn ifft(&self, evals: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut evals = evals.to_vec();
            self.ifft_in_place(&mut evals);
            evals
        }

        /// Compute an IFFT, modifying the vector in place.
        #[inline]
        pub(crate) fn ifft_in_place(&self, evals: &mut Vec<BlsScalar>) {
            evals.resize(self.size(), BlsScalar::zero());
            best_fft(evals, self.group_gen_inv, self.log_size_of_group);

            #[cfg(not(feature = "std"))]
            evals.iter_mut().for_each(|val| *val *= &self.size_inv);

            #[cfg(feature = "std")]
            evals.par_iter_mut().for_each(|val| *val *= &self.size_inv);
        }

        fn distribute_powers(coeffs: &mut [BlsScalar], g: BlsScalar) {
            let mut pow = BlsScalar::one();
            coeffs.iter_mut().for_each(|c| {
                *c *= &pow;
                pow *= &g
            })
        }

        /// Compute a FFT over a coset of the domain.
        pub(crate) fn coset_fft(&self, coeffs: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut coeffs = coeffs.to_vec();
            self.coset_fft_in_place(&mut coeffs);
            coeffs
        }

        /// Compute a FFT over a coset of the domain, modifying the input vector
        /// in place.
        fn coset_fft_in_place(&self, coeffs: &mut Vec<BlsScalar>) {
            Self::distribute_powers(coeffs, GENERATOR);
            self.fft_in_place(coeffs);
        }

        /// Compute an IFFT over a coset of the domain.
        pub(crate) fn coset_ifft(&self, evals: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut evals = evals.to_vec();
            self.coset_ifft_in_place(&mut evals);
            evals
        }

        /// Compute an IFFT over a coset of the domain, modifying the input
        /// vector in place.
        fn coset_ifft_in_place(&self, evals: &mut Vec<BlsScalar>) {
            self.ifft_in_place(evals);
            Self::distribute_powers(evals, self.generator_inv);
        }

        #[allow(clippy::needless_range_loop)]
        /// Evaluate all the lagrange polynomials defined by this domain at the
        /// point `tau`.
        pub(crate) fn evaluate_all_lagrange_coefficients(
            &self,
            tau: BlsScalar,
        ) -> Vec<BlsScalar> {
            // Evaluate all Lagrange polynomials
            let size = self.size as usize;
            let t_size = tau.pow(&[self.size, 0, 0, 0]);
            let one = BlsScalar::one();
            if t_size == BlsScalar::one() {
                let mut u = vec![BlsScalar::zero(); size];
                let mut omega_i = one;
                for i in 0..size {
                    if omega_i == tau {
                        u[i] = one;
                        break;
                    }
                    omega_i *= &self.group_gen;
                }
                u
            } else {
                use crate::util::batch_inversion;

                let mut l = (t_size - one) * self.size_inv;
                let mut r = one;
                let mut u = vec![BlsScalar::zero(); size];
                let mut ls = vec![BlsScalar::zero(); size];
                for i in 0..size {
                    u[i] = tau - r;
                    ls[i] = l;
                    l *= &self.group_gen;
                    r *= &self.group_gen;
                }

                batch_inversion(u.as_mut_slice());

                #[cfg(not(feature = "std"))]
                u.iter_mut().zip(ls).for_each(|(tau_minus_r, l)| {
                    *tau_minus_r = l * *tau_minus_r;
                });

                #[cfg(feature = "std")]
                u.par_iter_mut().zip(ls).for_each(|(tau_minus_r, l)| {
                    *tau_minus_r = l * *tau_minus_r;
                });

                u
            }
        }

        /// This evaluates the vanishing polynomial for this domain at tau.
        /// For multiplicative subgroups, this polynomial is `z(X) = X^self.size
        /// - 1`.
        pub(crate) fn evaluate_vanishing_polynomial(
            &self,
            tau: &BlsScalar,
        ) -> BlsScalar {
            tau.pow(&[self.size, 0, 0, 0]) - BlsScalar::one()
        }

        /// Given that the domain size is `D`  
        /// This function computes the `D` evaluation points for
        /// the vanishing polynomial of degree `n` over a coset
        pub(crate) fn compute_vanishing_poly_over_coset(
            &self,            // domain to evaluate over
            poly_degree: u64, // degree of the vanishing polynomial
        ) -> Evaluations {
            let v_h = self.vanishing_poly_over_coset(poly_degree).collect();
            Evaluations::from_vec_and_domain(v_h, *self)
        }

        pub(crate) fn matches_linear_poly_over_coset(
            &self,
            evaluations: &[BlsScalar],
        ) -> bool {
            if evaluations.len() != self.size() {
                return false;
            }

            let mut expected = GENERATOR;
            for evaluation in evaluations {
                if *evaluation != expected {
                    return false;
                }
                expected *= self.group_gen;
            }
            true
        }

        pub(crate) fn matches_vanishing_poly_over_coset(
            &self,
            poly_degree: u64,
            evaluations: &[BlsScalar],
        ) -> bool {
            poly_degree < self.size() as u64
                && evaluations.len() == self.size()
                && evaluations
                    .iter()
                    .copied()
                    .eq(self.vanishing_poly_over_coset(poly_degree))
        }

        fn vanishing_poly_over_coset(
            &self,
            poly_degree: u64,
        ) -> impl Iterator<Item = BlsScalar> {
            assert!((self.size() as u64) > poly_degree);
            let mut point = GENERATOR.pow(&[poly_degree, 0, 0, 0]);
            let step = self.group_gen.pow(&[poly_degree, 0, 0, 0]);

            (0..self.size()).map(move |_| {
                let evaluation = point - BlsScalar::one();
                point *= step;
                evaluation
            })
        }

        /// Return an iterator over the elements of the domain.
        pub(crate) fn elements(&self) -> Elements {
            Elements {
                cur_elem: BlsScalar::one(),
                cur_pow: 0,
                domain: *self,
            }
        }
    }

    #[cfg(not(feature = "std"))]
    fn best_fft(a: &mut [BlsScalar], omega: BlsScalar, log_n: u32) {
        serial_fft(a, omega, log_n)
    }

    #[cfg(feature = "std")]
    pub(super) const PARALLEL_FINAL_FFT_MIN_LEN: usize = 1 << 12;
    #[cfg(feature = "std")]
    pub(super) const PARALLEL_FINAL_FFT_MIN_THREADS: usize = 4;

    #[cfg(feature = "std")]
    pub(super) fn should_parallelize_final_fft_stages(
        len: usize,
        threads: usize,
    ) -> bool {
        len >= PARALLEL_FINAL_FFT_MIN_LEN
            && threads >= PARALLEL_FINAL_FFT_MIN_THREADS
    }

    #[cfg(feature = "std")]
    fn best_fft(a: &mut [BlsScalar], omega: BlsScalar, log_n: u32) {
        const PARALLEL_FFT_MIN_LEN: usize = 1 << 12;
        const PARALLEL_FFT_MIN_CHUNKS: usize = 4;

        let n = a.len();
        if n < PARALLEL_FFT_MIN_LEN {
            serial_fft(a, omega, log_n);
            return;
        }

        let n_u32 = n as u32;
        assert_eq!(n_u32, 1 << log_n);

        bitreverse_permute(a, log_n);

        let mut m = 1usize;
        for _ in 0..log_n {
            let w_m = omega.pow(&[(n_u32 / (2 * m as u32)) as u64, 0, 0, 0]);
            let chunk_len = 2 * m;
            let chunk_count = n / chunk_len;

            if chunk_count >= PARALLEL_FFT_MIN_CHUNKS {
                a.par_chunks_mut(chunk_len)
                    .for_each(|chunk| butterfly_chunk(chunk, m, w_m));
            } else if should_parallelize_final_fft_stages(
                n,
                rayon::current_num_threads(),
            ) {
                for chunk in a.chunks_mut(chunk_len) {
                    parallel_butterfly_chunk(chunk, m, w_m);
                }
            } else {
                for chunk in a.chunks_mut(chunk_len) {
                    butterfly_chunk(chunk, m, w_m);
                }
            }

            m *= 2;
        }
    }

    #[inline]
    fn bitreverse(mut n: u32, l: u32) -> u32 {
        let mut r = 0;
        for _ in 0..l {
            r = (r << 1) | (n & 1);
            n >>= 1;
        }
        r
    }

    fn bitreverse_permute(a: &mut [BlsScalar], log_n: u32) {
        for k in 0..a.len() as u32 {
            let rk = bitreverse(k, log_n);
            if k < rk {
                a.swap(rk as usize, k as usize);
            }
        }
    }

    pub(crate) fn serial_fft(
        a: &mut [BlsScalar],
        omega: BlsScalar,
        log_n: u32,
    ) {
        let n = a.len() as u32;
        assert_eq!(n, 1 << log_n);

        bitreverse_permute(a, log_n);

        let mut m = 1;
        for _ in 0..log_n {
            let w_m = omega.pow(&[(n / (2 * m)) as u64, 0, 0, 0]);

            for chunk in a.chunks_mut((2 * m) as usize) {
                butterfly_chunk(chunk, m as usize, w_m);
            }

            m *= 2;
        }
    }

    #[inline]
    fn butterfly_chunk(chunk: &mut [BlsScalar], m: usize, w_m: BlsScalar) {
        let (left, right) = chunk.split_at_mut(m);
        butterfly_range(left, right, w_m, BlsScalar::one());
    }

    #[inline]
    fn butterfly_range(
        left: &mut [BlsScalar],
        right: &mut [BlsScalar],
        w_m: BlsScalar,
        mut w: BlsScalar,
    ) {
        debug_assert_eq!(left.len(), right.len());

        for (left, right) in left.iter_mut().zip(right) {
            let mut t = *right;
            t *= &w;
            let mut tmp = *left;
            tmp -= &t;
            *right = tmp;
            *left += &t;
            w.mul_assign(&w_m);
        }
    }

    #[cfg(feature = "std")]
    fn parallel_butterfly_chunk(
        chunk: &mut [BlsScalar],
        m: usize,
        w_m: BlsScalar,
    ) {
        let (left, right) = chunk.split_at_mut(m);
        let range_len = m.div_ceil(rayon::current_num_threads());
        let range_count = m.div_ceil(range_len);
        let seed_step = w_m.pow_vartime(&[range_len as u64, 0, 0, 0]);
        let mut seed = BlsScalar::one();
        let seeds = (0..range_count)
            .map(|_| {
                let current = seed;
                seed *= &seed_step;
                current
            })
            .collect::<Vec<_>>();

        left.par_chunks_mut(range_len)
            .zip(right.par_chunks_mut(range_len))
            .zip(seeds)
            .for_each(|((left, right), seed)| {
                butterfly_range(left, right, w_m, seed)
            });
    }

    /// An iterator over the elements of the domain.
    #[derive(Debug)]
    pub(crate) struct Elements {
        cur_elem: BlsScalar,
        cur_pow: u64,
        domain: EvaluationDomain,
    }

    impl Iterator for Elements {
        type Item = BlsScalar;

        fn next(&mut self) -> Option<BlsScalar> {
            if self.cur_pow == self.domain.size {
                None
            } else {
                let cur_elem = self.cur_elem;
                self.cur_elem *= &self.domain.group_gen;
                self.cur_pow += 1;
                Some(cur_elem)
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use dusk_bls12_381::GENERATOR;

    use super::*;

    #[test]
    fn size_of_elements() {
        for coeffs in 1..10 {
            let size = 1 << coeffs;
            let domain = EvaluationDomain::new(size).unwrap();
            let domain_size = domain.size();
            assert_eq!(domain_size, domain.elements().count());
        }
    }

    #[test]
    fn elements_contents() {
        for coeffs in 1..10 {
            let size = 1 << coeffs;
            let domain = EvaluationDomain::new(size).unwrap();
            for (i, element) in domain.elements().enumerate() {
                assert_eq!(element, domain.group_gen.pow(&[i as u64, 0, 0, 0]));
            }
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn parallel_fft_matches_serial_fft_for_large_domain() {
        let domain = EvaluationDomain::new(1 << 12).unwrap();
        let input = (0..domain.size())
            .map(|i| BlsScalar::from((i as u64) + 1))
            .collect::<Vec<_>>();
        let mut serial = input.clone();
        crate::fft::domain::alloc::serial_fft(
            &mut serial,
            domain.group_gen,
            domain.log_size_of_group,
        );

        assert!(
            !crate::fft::domain::alloc::should_parallelize_final_fft_stages(
                1 << 11,
                8
            )
        );
        assert!(
            !crate::fft::domain::alloc::should_parallelize_final_fft_stages(
                1 << 12,
                3
            )
        );
        assert!(
            crate::fft::domain::alloc::should_parallelize_final_fft_stages(
                1 << 12,
                4
            )
        );

        for threads in [3, 4, 9] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let parallel = pool.install(|| domain.fft(&input));

            assert_eq!(parallel, serial, "failed with {threads} threads");

            let roundtrip = pool.install(|| domain.ifft(&parallel));
            assert_eq!(
                roundtrip, input,
                "roundtrip failed with {threads} threads"
            );
        }
    }

    #[test]
    fn linear_coset_evaluations_match_closed_form() {
        let domain = EvaluationDomain::new(1 << 8).unwrap();
        let evaluations =
            domain.coset_fft(&[BlsScalar::zero(), BlsScalar::one()]);

        assert!(domain.matches_linear_poly_over_coset(&evaluations));
        for (i, evaluation) in evaluations.iter().enumerate() {
            let expected =
                GENERATOR * domain.group_gen.pow(&[i as u64, 0, 0, 0]);
            assert_eq!(*evaluation, expected);
        }
        let mut incorrect = evaluations.clone();
        incorrect[0] = incorrect[1];
        assert!(!domain.matches_linear_poly_over_coset(&incorrect));
        assert!(!domain.matches_linear_poly_over_coset(&evaluations[..255]));
    }

    #[test]
    fn vanishing_coset_evaluations_match_closed_form() {
        let domain = EvaluationDomain::new(1 << 8).unwrap();
        let poly_degree = 1 << 5;
        let evaluations = domain.compute_vanishing_poly_over_coset(poly_degree);
        let coset_generator = GENERATOR.pow(&[poly_degree, 0, 0, 0]);

        for (i, evaluation) in evaluations.evals.iter().enumerate() {
            let expected = coset_generator
                * domain.group_gen.pow(&[poly_degree * i as u64, 0, 0, 0])
                - BlsScalar::one();
            assert_eq!(*evaluation, expected);
        }
    }

    #[test]
    fn vanishing_coset_evaluations_reject_invalid_degree() {
        let domain = EvaluationDomain::new(1 << 8).unwrap();
        let evaluations = vec![BlsScalar::zero(); domain.size()];

        assert!(!domain.matches_vanishing_poly_over_coset(
            domain.size() as u64,
            &evaluations,
        ));
        assert!(!domain.matches_vanishing_poly_over_coset(
            domain.size() as u64 + 1,
            &evaluations,
        ));
    }

    #[test]
    fn dusk_bytes_evaluation_domain_serde() {
        let eval_domain = EvaluationDomain::new(1 << (13 - 1))
            .expect("Error in eval_domain generation");
        let bytes = eval_domain.to_bytes();
        let obtained_eval_domain = EvaluationDomain::from_slice(&bytes)
            .expect("Deserialization error");
        assert_eq!(eval_domain, obtained_eval_domain);
    }
}
