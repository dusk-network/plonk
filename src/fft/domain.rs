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
            let mut evals = bitreverse_copy_from_slice(
                coeffs,
                self.size(),
                self.log_size_of_group,
            );
            best_fft_bitreversed(
                &mut evals,
                self.group_gen,
                self.log_size_of_group,
                None,
            );
            evals
        }

        /// Compute an IFFT.
        pub(crate) fn ifft(&self, evals: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut coeffs = bitreverse_copy_from_slice(
                evals,
                self.size(),
                self.log_size_of_group,
            );
            self.ifft_bitreversed_with_roots(&mut coeffs, None);
            coeffs
        }

        /// Compute an IFFT using precomputed inverse-domain roots of unity.
        pub(crate) fn ifft_with_roots(
            &self,
            evals: &[BlsScalar],
            roots: &[BlsScalar],
        ) -> Vec<BlsScalar> {
            let mut coeffs = bitreverse_copy_from_slice(
                evals,
                self.size(),
                self.log_size_of_group,
            );
            self.ifft_bitreversed_with_roots(&mut coeffs, Some(roots));
            coeffs
        }

        /// Compute a single-threaded IFFT using precomputed inverse-domain
        /// roots of unity. Used when outer callers already run multiple IFFTs
        /// in parallel and nested Rayon barriers would add overhead.
        pub(crate) fn serial_ifft_with_roots(
            &self,
            evals: &[BlsScalar],
            roots: &[BlsScalar],
        ) -> Vec<BlsScalar> {
            let n = self.size();
            let log_n = self.log_size_of_group;
            let len = evals.len().min(n);
            let mut coeffs = vec![BlsScalar::zero(); n];
            for (k, &val) in evals[..len].iter().enumerate() {
                coeffs[bitreverse(k as u32, log_n) as usize] = val;
            }
            serial_fft_bitreversed(
                &mut coeffs,
                self.group_gen_inv,
                log_n,
                Some(roots),
            );
            for val in &mut coeffs {
                *val *= &self.size_inv;
            }
            coeffs
        }

        /// Compute an IFFT, modifying the vector in place.
        #[inline]
        pub(crate) fn ifft_in_place(&self, evals: &mut Vec<BlsScalar>) {
            let n = self.size();
            let log_n = self.log_size_of_group;
            if use_parallel_bitrev_copy(n) {
                *evals = bitreverse_copy_from_slice(evals, n, log_n);
            } else {
                evals.resize(n, BlsScalar::zero());
                bitreverse_permute_serial(evals, log_n);
            }
            self.ifft_bitreversed_with_roots(evals, None);
        }

        fn ifft_bitreversed_with_roots(
            &self,
            evals: &mut [BlsScalar],
            roots: Option<&[BlsScalar]>,
        ) {
            best_fft_bitreversed(
                evals,
                self.group_gen_inv,
                self.log_size_of_group,
                roots,
            );
            scale_in_place(evals, self.size_inv);
        }

        /// Precompute the `n / 2` powers of `self.group_gen` for reusing across
        /// multiple FFTs over the same domain.
        pub(crate) fn precompute_fft_roots(&self) -> Vec<BlsScalar> {
            compute_roots(self.group_gen, self.size() / 2)
        }

        /// Precompute the `n / 2` powers of `self.group_gen_inv` for reusing
        /// across multiple IFFTs over the same domain.
        pub(crate) fn precompute_ifft_roots(&self) -> Vec<BlsScalar> {
            compute_roots(self.group_gen_inv, self.size() / 2)
        }

        /// Compute a FFT over a coset of the domain.
        pub(crate) fn coset_fft(&self, coeffs: &[BlsScalar]) -> Vec<BlsScalar> {
            self.coset_fft_inner(coeffs, None)
        }

        /// Compute a FFT over a coset of the domain using precomputed domain
        /// roots of unity.
        pub(crate) fn coset_fft_with_roots(
            &self,
            coeffs: &[BlsScalar],
            roots: &[BlsScalar],
        ) -> Vec<BlsScalar> {
            self.coset_fft_inner(coeffs, Some(roots))
        }

        fn coset_fft_inner(
            &self,
            coeffs: &[BlsScalar],
            roots: Option<&[BlsScalar]>,
        ) -> Vec<BlsScalar> {
            let n = self.size();
            let len = coeffs.len().min(n);
            if len == 0 {
                return vec![BlsScalar::zero(); n];
            }

            let mut evals = coset_bitreverse_from_slice(
                &coeffs[..len],
                n,
                self.log_size_of_group,
                GENERATOR,
            );
            best_fft_bitreversed(
                &mut evals,
                self.group_gen,
                self.log_size_of_group,
                roots,
            );
            evals
        }

        /// Compute an IFFT over a coset of the domain.
        #[cfg(test)]
        pub(crate) fn coset_ifft(&self, evals: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut coeffs = bitreverse_copy_from_slice(
                evals,
                self.size(),
                self.log_size_of_group,
            );
            self.coset_ifft_bitreversed(&mut coeffs);
            coeffs
        }

        /// Compute an IFFT over a coset of the domain, modifying the input
        /// vector in place.
        pub(crate) fn coset_ifft_in_place(&self, evals: &mut Vec<BlsScalar>) {
            let n = self.size();
            let log_n = self.log_size_of_group;
            if use_parallel_bitrev_copy(n) {
                *evals = bitreverse_copy_from_slice(evals, n, log_n);
            } else {
                evals.resize(n, BlsScalar::zero());
                bitreverse_permute_serial(evals, log_n);
            }
            self.coset_ifft_bitreversed(evals);
        }

        fn coset_ifft_bitreversed(&self, evals: &mut [BlsScalar]) {
            best_fft_bitreversed(
                evals,
                self.group_gen_inv,
                self.log_size_of_group,
                None,
            );
            distribute_powers_scaled(evals, self.generator_inv, self.size_inv);
        }

        /// Evaluate the first Lagrange polynomial `L_1(tau)` for this domain.
        pub(crate) fn evaluate_first_lagrange_coefficient(
            &self,
            tau: BlsScalar,
        ) -> BlsScalar {
            let one = BlsScalar::one();
            let t_size = tau.pow(&[self.size, 0, 0, 0]);
            if t_size == one {
                if tau == one { one } else { BlsScalar::zero() }
            } else {
                let l = (t_size - one) * self.size_inv;
                l * (tau - one).invert().unwrap()
            }
        }

        #[allow(clippy::needless_range_loop)]
        /// Evaluate all the lagrange polynomials defined by this domain at the
        /// point `tau`.
        #[cfg(test)]
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
            evaluations: impl ExactSizeIterator<Item = BlsScalar>,
        ) -> bool {
            if evaluations.len() != self.size() {
                return false;
            }

            let mut expected = GENERATOR;
            for evaluation in evaluations {
                if evaluation != expected {
                    return false;
                }
                expected *= self.group_gen;
            }
            true
        }

        /// Whether `evaluations` are the coset evaluations of the polynomial
        /// with `coeffs`, as preprocessing caches them for selectors.
        pub(crate) fn matches_coset_evaluations(
            &self,
            coeffs: &[BlsScalar],
            evaluations: impl ExactSizeIterator<Item = BlsScalar>,
        ) -> bool {
            coeffs.len() <= self.size()
                && evaluations.len() == self.size()
                && evaluations.eq(self.coset_fft(coeffs))
        }

        pub(crate) fn matches_vanishing_poly_over_coset(
            &self,
            poly_degree: u64,
            evaluations: impl ExactSizeIterator<Item = BlsScalar>,
        ) -> bool {
            poly_degree < self.size() as u64
                && evaluations.len() == self.size()
                && evaluations.eq(self.vanishing_poly_over_coset(poly_degree))
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

    #[cfg(feature = "std")]
    const PARALLEL_SCALE_MIN_LEN: usize = 1 << 14;
    #[cfg(feature = "std")]
    const PARALLEL_DISTRIBUTE_MIN_LEN: usize = 1 << 14;
    #[cfg(feature = "std")]
    const PARALLEL_BITREV_COPY_MIN_LEN: usize = 1 << 15;
    #[cfg(feature = "std")]
    const PARALLEL_ROOTS_MIN_LEN: usize = 1 << 14;
    #[cfg(feature = "std")]
    const PARALLEL_FFT_MIN_LEN: usize = 1 << 15;
    #[cfg(feature = "std")]
    const MIN_SUB_FFT_LEN: usize = 1 << 11;

    #[inline]
    fn use_parallel_bitrev_copy(n: usize) -> bool {
        #[cfg(feature = "std")]
        {
            n >= PARALLEL_BITREV_COPY_MIN_LEN
                && rayon::current_num_threads() > 1
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = n;
            false
        }
    }

    fn scale_in_place(values: &mut [BlsScalar], scale: BlsScalar) {
        #[cfg(feature = "std")]
        {
            let threads = rayon::current_num_threads();
            if values.len() >= PARALLEL_SCALE_MIN_LEN && threads > 1 {
                let chunk_len = values.len().div_ceil(threads);
                values.par_chunks_mut(chunk_len).for_each(|chunk| {
                    for val in chunk {
                        *val *= &scale;
                    }
                });
                return;
            }
        }

        for val in values {
            *val *= &scale;
        }
    }

    pub(super) fn distribute_powers_scaled(
        coeffs: &mut [BlsScalar],
        g: BlsScalar,
        scale: BlsScalar,
    ) {
        #[cfg(feature = "std")]
        {
            let threads = rayon::current_num_threads();
            if coeffs.len() >= PARALLEL_DISTRIBUTE_MIN_LEN && threads > 1 {
                let chunk_len = coeffs.len().div_ceil(threads);
                let step = g.pow_vartime(&[chunk_len as u64, 0, 0, 0]);
                coeffs.par_chunks_mut(chunk_len).enumerate().for_each(
                    |(chunk_idx, chunk)| {
                        let mut pow = scale
                            * step.pow_vartime(&[chunk_idx as u64, 0, 0, 0]);
                        for c in chunk {
                            *c *= &pow;
                            pow *= &g;
                        }
                    },
                );
                return;
            }
        }

        let mut pow = scale;
        for c in coeffs {
            *c *= &pow;
            pow *= &g;
        }
    }

    fn bitreverse_copy_from_slice(
        src: &[BlsScalar],
        n: usize,
        log_n: u32,
    ) -> Vec<BlsScalar> {
        let len = src.len().min(n);

        #[cfg(feature = "std")]
        if n >= PARALLEL_BITREV_COPY_MIN_LEN && rayon::current_num_threads() > 1
        {
            return (0..n)
                .into_par_iter()
                .map(|k| {
                    let rk = bitreverse(k as u32, log_n) as usize;
                    if rk < len { src[rk] } else { BlsScalar::zero() }
                })
                .collect();
        }

        let mut out = vec![BlsScalar::zero(); n];
        for (k, &val) in src[..len].iter().enumerate() {
            out[bitreverse(k as u32, log_n) as usize] = val;
        }
        out
    }

    fn coset_bitreverse_from_slice(
        src: &[BlsScalar],
        n: usize,
        log_n: u32,
        g: BlsScalar,
    ) -> Vec<BlsScalar> {
        #[cfg(feature = "std")]
        if n >= PARALLEL_BITREV_COPY_MIN_LEN && rayon::current_num_threads() > 1
        {
            let len = src.len();
            let mut scaled = src.to_vec();
            distribute_powers_scaled(&mut scaled, g, BlsScalar::one());
            return (0..n)
                .into_par_iter()
                .map(|k| {
                    let rk = bitreverse(k as u32, log_n) as usize;
                    if rk < len {
                        scaled[rk]
                    } else {
                        BlsScalar::zero()
                    }
                })
                .collect();
        }

        let mut out = vec![BlsScalar::zero(); n];
        let mut pow = BlsScalar::one();
        for (k, &val) in src.iter().enumerate() {
            out[bitreverse(k as u32, log_n) as usize] = val * pow;
            pow *= &g;
        }
        out
    }

    fn compute_roots(omega: BlsScalar, half_n: usize) -> Vec<BlsScalar> {
        if half_n == 0 {
            return Vec::new();
        }

        #[cfg(feature = "std")]
        {
            let threads = rayon::current_num_threads();
            if half_n >= PARALLEL_ROOTS_MIN_LEN && threads > 1 {
                let mut roots = vec![BlsScalar::zero(); half_n];
                let chunk_len = half_n.div_ceil(threads);
                let step = omega.pow_vartime(&[chunk_len as u64, 0, 0, 0]);
                roots.par_chunks_mut(chunk_len).enumerate().for_each(
                    |(chunk_idx, chunk)| {
                        let mut cur =
                            step.pow_vartime(&[chunk_idx as u64, 0, 0, 0]);
                        for slot in chunk {
                            *slot = cur;
                            cur *= &omega;
                        }
                    },
                );
                return roots;
            }
        }

        let mut roots = Vec::with_capacity(half_n);
        let mut cur = BlsScalar::one();
        for _ in 0..half_n {
            roots.push(cur);
            cur *= &omega;
        }
        roots
    }

    #[cfg(not(feature = "std"))]
    fn best_fft_bitreversed(
        a: &mut [BlsScalar],
        omega: BlsScalar,
        log_n: u32,
        precomputed_roots: Option<&[BlsScalar]>,
    ) {
        serial_fft_bitreversed(a, omega, log_n, precomputed_roots);
    }

    #[cfg(feature = "std")]
    fn choose_log_chunks(log_n: u32, threads: usize) -> u32 {
        let n = 1usize << log_n;
        if n < PARALLEL_FFT_MIN_LEN || threads <= 1 {
            return 0;
        }
        // Keep `log_chunks` even so Phase 2 consists strictly of radix-4
        // stages (no extra Rayon barrier for a lone radix-2 stage), while any
        // odd parity of `log_n` is absorbed inside Phase 1's zero-mul m=1 pass.
        let max_log_chunks = ((n / MIN_SUB_FFT_LEN).trailing_zeros()) & !1;
        let target_chunks = (threads.saturating_mul(2)).next_power_of_two();
        let target_log = (target_chunks.trailing_zeros() + 1) & !1;
        target_log.min(max_log_chunks)
    }

    #[cfg(feature = "std")]
    fn best_fft_bitreversed(
        a: &mut [BlsScalar],
        omega: BlsScalar,
        log_n: u32,
        precomputed_roots: Option<&[BlsScalar]>,
    ) {
        let n = a.len();
        assert_eq!(n, 1usize << log_n);
        if log_n == 0 {
            return;
        }

        let threads = rayon::current_num_threads();
        let log_chunks = choose_log_chunks(log_n, threads);
        if log_chunks == 0 {
            serial_fft_bitreversed(a, omega, log_n, precomputed_roots);
            return;
        }

        let owned_roots;
        let roots = match precomputed_roots {
            Some(r) => {
                debug_assert_eq!(r.len(), n / 2);
                r
            }
            None => {
                owned_roots = compute_roots(omega, n / 2);
                &owned_roots
            }
        };

        let log_sub_n = log_n - log_chunks;
        let sub_n = 1usize << log_sub_n;
        let num_chunks = 1usize << log_chunks;

        // Build a compact contiguous root table for the L2-resident sub-FFTs.
        let sub_roots: Vec<BlsScalar> =
            (0..sub_n / 2).map(|k| roots[k * num_chunks]).collect();

        // Phase 1: execute all `log_sub_n` inner stages independently per chunk
        // in a single Rayon parallel pass (zero intermediate barriers).
        a.par_chunks_exact_mut(sub_n).for_each(|chunk| {
            radix4_fft_with_roots(chunk, log_sub_n, &sub_roots);
        });

        // Phase 2: execute the remaining `log_chunks / 2` cross-chunk radix-4
        // stages.
        let quarter_n = n / 4;
        let mut m = sub_n;
        let mut remaining = log_chunks;
        debug_assert_eq!(remaining & 1, 0);

        while remaining >= 2 {
            let step = quarter_n / m;
            parallel_radix4_stage(a, m, roots, quarter_n, step, threads);
            m *= 4;
            remaining -= 2;
        }
    }

    #[inline]
    pub(super) fn bitreverse(n: u32, l: u32) -> u32 {
        if l == 0 {
            0
        } else {
            n.reverse_bits() >> (32 - l)
        }
    }

    fn bitreverse_permute_serial(a: &mut [BlsScalar], log_n: u32) {
        if log_n <= 1 {
            return;
        }
        for k in 0..a.len() as u32 {
            let rk = bitreverse(k, log_n);
            if k < rk {
                a.swap(rk as usize, k as usize);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn serial_fft(
        a: &mut [BlsScalar],
        omega: BlsScalar,
        log_n: u32,
    ) {
        let n = a.len();
        assert_eq!(n, 1usize << log_n);
        if log_n == 0 {
            return;
        }

        bitreverse_permute_serial(a, log_n);

        if log_n == 1 {
            let u = a[0];
            let v = a[1];
            a[0] = u + v;
            a[1] = u - v;
            return;
        }

        let mut roots = Vec::with_capacity(n / 2);
        let mut cur = BlsScalar::one();
        for _ in 0..n / 2 {
            roots.push(cur);
            cur *= &omega;
        }
        radix4_fft_with_roots(a, log_n, &roots);
    }

    fn serial_fft_bitreversed(
        a: &mut [BlsScalar],
        omega: BlsScalar,
        log_n: u32,
        precomputed_roots: Option<&[BlsScalar]>,
    ) {
        let n = a.len();
        if log_n == 0 {
            return;
        }
        if log_n == 1 {
            let u = a[0];
            let v = a[1];
            a[0] = u + v;
            a[1] = u - v;
            return;
        }

        let owned_roots;
        let roots = match precomputed_roots {
            Some(r) => {
                debug_assert_eq!(r.len(), n / 2);
                r
            }
            None => {
                owned_roots = compute_roots(omega, n / 2);
                &owned_roots
            }
        };
        radix4_fft_with_roots(a, log_n, roots);
    }

    fn radix4_fft_with_roots(
        a: &mut [BlsScalar],
        log_n: u32,
        roots: &[BlsScalar],
    ) {
        let n = a.len();
        debug_assert_eq!(n, 1usize << log_n);
        if log_n == 0 {
            return;
        }
        if log_n == 1 {
            let u = a[0];
            let v = a[1];
            a[0] = u + v;
            a[1] = u - v;
            return;
        }

        let quarter_n = n / 4;
        let i4 = roots[quarter_n];

        let mut m = if log_n & 1 == 1 {
            // Single radix-2 stage at m = 1 (all twiddles are 1: 0 muls).
            for chunk in a.as_chunks_mut::<2>().0 {
                let u = chunk[0];
                let v = chunk[1];
                chunk[0] = u + v;
                chunk[1] = u - v;
            }
            2usize
        } else {
            // Specialized radix-4 stage at m = 1 (only 1 mul per 4 elements).
            for chunk in a.as_chunks_mut::<4>().0 {
                let a0 = chunk[0];
                let a1 = chunk[1];
                let a2 = chunk[2];
                let a3 = chunk[3];

                let u0 = a0 + a1;
                let u1 = a0 - a1;
                let u2 = a2 + a3;
                let v3 = (a2 - a3) * i4;

                chunk[0] = u0 + u2;
                chunk[2] = u0 - u2;
                chunk[1] = u1 + v3;
                chunk[3] = u1 - v3;
            }
            4usize
        };

        // Specialized radix-4 stage at m = 2 (odd log_n >= 3): all twiddles
        // stay in registers.
        if m == 2 {
            let step = quarter_n / 2;
            let w1 = roots[step];
            let w2 = i4;
            let w1_i4 = roots[step + quarter_n];

            for block in a.as_chunks_mut::<8>().0 {
                // j = 0
                let a0 = block[0];
                let a1 = block[2];
                let a2 = block[4];
                let a3 = block[6];
                let u0 = a0 + a1;
                let u1 = a0 - a1;
                let u2 = a2 + a3;
                let v3 = (a2 - a3) * i4;
                block[0] = u0 + u2;
                block[4] = u0 - u2;
                block[2] = u1 + v3;
                block[6] = u1 - v3;

                // j = 1
                let a0 = block[1];
                let t1 = block[3] * w2;
                let a2 = block[5];
                let t3 = block[7] * w2;
                let u0 = a0 + t1;
                let u1 = a0 - t1;
                let v2 = (a2 + t3) * w1;
                let v3 = (a2 - t3) * w1_i4;
                block[1] = u0 + v2;
                block[5] = u0 - v2;
                block[3] = u1 + v3;
                block[7] = u1 - v3;
            }
            m = 8;
        }

        #[cfg(feature = "std")]
        {
            // Stack-backed contiguous L1 twiddle cache for small `m` where
            // striding through `roots` would touch sparse cache lines. Kept
            // off `no_std` so embedded targets (e.g. Thumb) avoid a 6 KiB
            // stack frame.
            const LOCAL_TWIDDLE_MAX_M: usize = 64;
            let mut local_twiddles =
                [(BlsScalar::zero(), BlsScalar::zero(), BlsScalar::zero());
                    LOCAL_TWIDDLE_MAX_M];

            while m < n {
                let step = quarter_n / m;
                if m <= LOCAL_TWIDDLE_MAX_M {
                    for (j, slot) in local_twiddles[..m].iter_mut().enumerate()
                    {
                        let idx = j * step;
                        *slot = (
                            roots[idx],
                            roots[idx << 1],
                            roots[idx + quarter_n],
                        );
                    }
                    let twiddles = &local_twiddles[..m];
                    for block in a.chunks_exact_mut(4 * m) {
                        let (left, right) = block.split_at_mut(2 * m);
                        let (q0, q1) = left.split_at_mut(m);
                        let (q2, q3) = right.split_at_mut(m);
                        radix4_butterfly_j0(q0, q1, q2, q3, &i4);
                        for j in 1..m {
                            let (w1, w2, w1_i4) = &twiddles[j];
                            let a0 = q0[j];
                            let t1 = q1[j] * w2;
                            let a2 = q2[j];
                            let t3 = q3[j] * w2;

                            let u0 = a0 + t1;
                            let u1 = a0 - t1;
                            let v2 = (a2 + t3) * w1;
                            let v3 = (a2 - t3) * w1_i4;

                            q0[j] = u0 + v2;
                            q2[j] = u0 - v2;
                            q1[j] = u1 + v3;
                            q3[j] = u1 - v3;
                        }
                    }
                } else {
                    for block in a.chunks_exact_mut(4 * m) {
                        radix4_block(block, m, roots, quarter_n, step);
                    }
                }
                m *= 4;
            }
        }

        #[cfg(not(feature = "std"))]
        while m < n {
            let step = quarter_n / m;
            for block in a.chunks_exact_mut(4 * m) {
                radix4_block(block, m, roots, quarter_n, step);
            }
            m *= 4;
        }
    }

    #[inline(always)]
    fn radix4_butterfly_j0(
        q0: &mut [BlsScalar],
        q1: &mut [BlsScalar],
        q2: &mut [BlsScalar],
        q3: &mut [BlsScalar],
        i4: &BlsScalar,
    ) {
        let a0 = q0[0];
        let a1 = q1[0];
        let a2 = q2[0];
        let a3 = q3[0];

        let u0 = a0 + a1;
        let u1 = a0 - a1;
        let u2 = a2 + a3;
        let v3 = (a2 - a3) * i4;

        q0[0] = u0 + u2;
        q2[0] = u0 - u2;
        q1[0] = u1 + v3;
        q3[0] = u1 - v3;
    }

    #[inline]
    fn radix4_block(
        block: &mut [BlsScalar],
        m: usize,
        roots: &[BlsScalar],
        quarter_n: usize,
        step: usize,
    ) {
        let (left, right) = block.split_at_mut(2 * m);
        let (q0, q1) = left.split_at_mut(m);
        let (q2, q3) = right.split_at_mut(m);
        radix4_range(q0, q1, q2, q3, 0, roots, quarter_n, step);
    }

    #[inline]
    fn radix4_range(
        q0: &mut [BlsScalar],
        q1: &mut [BlsScalar],
        q2: &mut [BlsScalar],
        q3: &mut [BlsScalar],
        j_start: usize,
        roots: &[BlsScalar],
        quarter_n: usize,
        step: usize,
    ) {
        let len = q0.len();
        debug_assert_eq!(len, q1.len());
        debug_assert_eq!(len, q2.len());
        debug_assert_eq!(len, q3.len());
        if len == 0 {
            return;
        }

        let start = if j_start == 0 {
            radix4_butterfly_j0(q0, q1, q2, q3, &roots[quarter_n]);
            1
        } else {
            0
        };

        let mut idx = (j_start + start) * step;
        for k in start..len {
            let w1 = &roots[idx];
            let w2 = &roots[idx << 1];
            let w1_i4 = &roots[idx + quarter_n];

            let a0 = q0[k];
            let t1 = q1[k] * w2;
            let a2 = q2[k];
            let t3 = q3[k] * w2;

            let u0 = a0 + t1;
            let u1 = a0 - t1;
            let v2 = (a2 + t3) * w1;
            let v3 = (a2 - t3) * w1_i4;

            q0[k] = u0 + v2;
            q2[k] = u0 - v2;
            q1[k] = u1 + v3;
            q3[k] = u1 - v3;

            idx += step;
        }
    }

    #[cfg(feature = "std")]
    fn parallel_radix4_stage(
        a: &mut [BlsScalar],
        m: usize,
        roots: &[BlsScalar],
        quarter_n: usize,
        step: usize,
        threads: usize,
    ) {
        let block_len = 4 * m;
        let num_blocks = a.len() / block_len;
        if num_blocks >= threads * 2 {
            a.par_chunks_exact_mut(block_len).for_each(|block| {
                radix4_block(block, m, roots, quarter_n, step);
            });
        } else if num_blocks == 1 {
            let range_len = m.div_ceil(threads.saturating_mul(2)).max(256);
            let (left, right) = a.split_at_mut(2 * m);
            let (q0, q1) = left.split_at_mut(m);
            let (q2, q3) = right.split_at_mut(m);
            q0.par_chunks_mut(range_len)
                .zip(q1.par_chunks_mut(range_len))
                .zip(q2.par_chunks_mut(range_len))
                .zip(q3.par_chunks_mut(range_len))
                .enumerate()
                .for_each(|(chunk_idx, (((c0, c1), c2), c3))| {
                    radix4_range(
                        c0,
                        c1,
                        c2,
                        c3,
                        chunk_idx * range_len,
                        roots,
                        quarter_n,
                        step,
                    );
                });
        } else {
            let target_tasks = threads.saturating_mul(2);
            let sub_chunks = target_tasks.div_ceil(num_blocks).max(1);
            let range_len = m.div_ceil(sub_chunks).max(256);
            a.par_chunks_exact_mut(block_len).for_each(|block| {
                let (left, right) = block.split_at_mut(2 * m);
                let (q0, q1) = left.split_at_mut(m);
                let (q2, q3) = right.split_at_mut(m);
                q0.par_chunks_mut(range_len)
                    .zip(q1.par_chunks_mut(range_len))
                    .zip(q2.par_chunks_mut(range_len))
                    .zip(q3.par_chunks_mut(range_len))
                    .enumerate()
                    .for_each(|(chunk_idx, (((c0, c1), c2), c3))| {
                        radix4_range(
                            c0,
                            c1,
                            c2,
                            c3,
                            chunk_idx * range_len,
                            roots,
                            quarter_n,
                            step,
                        );
                    });
            });
        }
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
    use ::alloc::vec::Vec;
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

    fn reference_bitreverse(mut n: u32, l: u32) -> u32 {
        let mut r = 0;
        for _ in 0..l {
            r = (r << 1) | (n & 1);
            n >>= 1;
        }
        r
    }

    fn reference_naive_dft(
        input: &[BlsScalar],
        omega: BlsScalar,
    ) -> Vec<BlsScalar> {
        let n = input.len();
        (0..n)
            .map(|i| {
                let x = omega.pow(&[i as u64, 0, 0, 0]);
                let mut acc = BlsScalar::zero();
                let mut x_pow = BlsScalar::one();
                for coeff in input {
                    acc += *coeff * x_pow;
                    x_pow *= x;
                }
                acc
            })
            .collect()
    }

    fn reference_radix2_fft(a: &mut [BlsScalar], omega: BlsScalar, log_n: u32) {
        let n = a.len() as u32;
        assert_eq!(n, 1 << log_n);

        for k in 0..n {
            let rk = reference_bitreverse(k, log_n);
            if k < rk {
                a.swap(rk as usize, k as usize);
            }
        }

        let mut m = 1u32;
        for _ in 0..log_n {
            let w_m = omega.pow(&[(n / (2 * m)) as u64, 0, 0, 0]);
            for chunk in a.chunks_mut((2 * m) as usize) {
                let (left, right) = chunk.split_at_mut(m as usize);
                let mut w = BlsScalar::one();
                for (l, r) in left.iter_mut().zip(right.iter_mut()) {
                    let t = *r * w;
                    *r = *l - t;
                    *l += t;
                    w *= w_m;
                }
            }
            m *= 2;
        }
    }

    #[test]
    fn bitreverse_matches_reference_across_widths() {
        assert_eq!(crate::fft::domain::alloc::bitreverse(0, 0), 0);
        assert_eq!(crate::fft::domain::alloc::bitreverse(1, 0), 0);
        for l in 1..=12u32 {
            for k in 0..(1u32 << l) {
                assert_eq!(
                    crate::fft::domain::alloc::bitreverse(k, l),
                    reference_bitreverse(k, l),
                    "mismatch for k={k}, l={l}"
                );
            }
        }
        for k in [0u32, 1, 2, 0x1234_5678 & ((1 << 31) - 1), (1 << 31) - 1] {
            assert_eq!(
                crate::fft::domain::alloc::bitreverse(k, 31),
                reference_bitreverse(k, 31)
            );
        }
    }

    #[test]
    fn fft_matches_naive_dft_for_small_domains() {
        for log_n in 0..=6u32 {
            let n = 1usize << log_n;
            let domain = EvaluationDomain::new(n).unwrap();
            let input: Vec<BlsScalar> = (0..n)
                .map(|i| BlsScalar::from((i as u64 + 1) * 7 + 3))
                .collect();

            let expected_fft = reference_naive_dft(&input, domain.group_gen);
            let mut serial = input.clone();
            crate::fft::domain::alloc::serial_fft(
                &mut serial,
                domain.group_gen,
                log_n,
            );
            assert_eq!(serial, expected_fft, "serial_fft failed for 2^{log_n}");
            assert_eq!(
                domain.fft(&input),
                expected_fft,
                "fft failed for 2^{log_n}"
            );
            assert_eq!(
                domain.ifft(&expected_fft),
                input,
                "ifft failed for 2^{log_n}"
            );

            // Coset FFT against naive DFT on scaled coefficients.
            let mut scaled = input.clone();
            let mut pow = BlsScalar::one();
            for c in &mut scaled {
                *c *= pow;
                pow *= GENERATOR;
            }
            let expected_coset = reference_naive_dft(&scaled, domain.group_gen);
            let actual_coset = domain.coset_fft(&input);
            assert_eq!(
                actual_coset, expected_coset,
                "coset_fft failed for 2^{log_n}"
            );
            assert_eq!(
                domain.coset_ifft(&actual_coset),
                input,
                "coset_ifft failed for 2^{log_n}"
            );
        }
    }

    #[test]
    fn fft_and_coset_roundtrip_match_radix2_for_all_log_n_0_through_15() {
        for log_n in 0..=15u32 {
            let n = 1usize << log_n;
            let domain = EvaluationDomain::new(n).unwrap();
            let input: Vec<BlsScalar> = (0..n)
                .map(|i| BlsScalar::from((i as u64).wrapping_mul(13) + 5))
                .collect();

            let mut expected = input.clone();
            reference_radix2_fft(&mut expected, domain.group_gen, log_n);

            let mut serial = input.clone();
            crate::fft::domain::alloc::serial_fft(
                &mut serial,
                domain.group_gen,
                log_n,
            );
            assert_eq!(serial, expected, "serial_fft mismatch for 2^{log_n}");

            let actual = domain.fft(&input);
            assert_eq!(actual, expected, "domain.fft mismatch for 2^{log_n}");
            let inv_roots = domain.precompute_ifft_roots();
            assert_eq!(
                domain.ifft(&actual),
                input,
                "ifft roundtrip failed for 2^{log_n}"
            );
            assert_eq!(
                domain.ifft_with_roots(&actual, &inv_roots),
                input,
                "ifft_with_roots roundtrip failed for 2^{log_n}"
            );
            assert_eq!(
                domain.serial_ifft_with_roots(&actual, &inv_roots),
                input,
                "serial_ifft_with_roots roundtrip failed for 2^{log_n}"
            );

            let coset = domain.coset_fft(&input);
            assert_eq!(
                domain.coset_ifft(&coset),
                input,
                "coset_ifft roundtrip failed for 2^{log_n}"
            );

            // Empty input yields all zeros.
            assert_eq!(domain.coset_fft(&[]), vec![BlsScalar::zero(); n]);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn parallel_fft_matches_serial_fft_for_large_domain() {
        for log_n in [0u32, 1, 2, 3, 7, 12, 13, 14, 15, 16] {
            let domain = EvaluationDomain::new(1 << log_n).unwrap();
            let input = (0..domain.size())
                .map(|i| BlsScalar::from((i as u64) + 1))
                .collect::<Vec<_>>();
            let short_input =
                &input[..input.len().min((domain.size() / 8) + 3)];

            let mut serial = input.clone();
            crate::fft::domain::alloc::serial_fft(
                &mut serial,
                domain.group_gen,
                domain.log_size_of_group,
            );
            let serial_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap();
            let expected_coset_short =
                serial_pool.install(|| domain.coset_fft(short_input));
            let expected_coset_full =
                serial_pool.install(|| domain.coset_fft(&input));

            for threads in [1, 3, 4, 8, 9] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap();
                let parallel = pool.install(|| domain.fft(&input));
                assert_eq!(
                    parallel, serial,
                    "fft failed for 2^{log_n} with {threads} threads"
                );
                assert_eq!(
                    pool.install(|| domain.ifft(&parallel)),
                    input,
                    "ifft roundtrip failed for 2^{log_n} with {threads} threads"
                );

                let (coset_short, coset_full, coset_roundtrip) =
                    pool.install(|| {
                        let cs = domain.coset_fft(short_input);
                        let cf = domain.coset_fft(&input);
                        let mut inv = cf.clone();
                        domain.coset_ifft_in_place(&mut inv);
                        (cs, cf, inv)
                    });
                assert_eq!(coset_short, expected_coset_short);
                assert_eq!(coset_full, expected_coset_full);
                assert_eq!(coset_roundtrip, input);
            }
        }
    }

    #[test]
    fn distribute_powers_matches_serial_reference() {
        let g = GENERATOR;
        let scale = BlsScalar::from(17u64);

        let serial_reference =
            |len: usize, scale: BlsScalar| -> Vec<BlsScalar> {
                let mut out: Vec<_> = (0..len)
                    .map(|i| BlsScalar::from((i as u64) * 3 + 1))
                    .collect();
                let mut pow = scale;
                for c in &mut out {
                    *c *= pow;
                    pow *= g;
                }
                out
            };

        for len in [0usize, 1, 7, 1024, 16384, 16385, 32768] {
            let input: Vec<_> = (0..len)
                .map(|i| BlsScalar::from((i as u64) * 3 + 1))
                .collect();
            let expected_scaled = serial_reference(len, scale);

            let mut actual_scaled = input.clone();
            crate::fft::domain::alloc::distribute_powers_scaled(
                &mut actual_scaled,
                g,
                scale,
            );
            assert_eq!(actual_scaled, expected_scaled);

            #[cfg(feature = "std")]
            for threads in [1, 3, 8] {
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap();
                let par_scaled = pool.install(|| {
                    let mut s = input.clone();
                    crate::fft::domain::alloc::distribute_powers_scaled(
                        &mut s, g, scale,
                    );
                    s
                });
                assert_eq!(par_scaled, expected_scaled);
            }
        }
    }

    #[test]
    fn evaluate_first_lagrange_coefficient_matches_all_lagrange() {
        for log_n in [1u32, 2, 5, 8] {
            let domain = EvaluationDomain::new(1 << log_n).unwrap();
            let omega = domain.group_gen;
            for tau in [
                BlsScalar::one(),
                omega,
                omega.pow(&[3, 0, 0, 0]),
                BlsScalar::zero(),
                GENERATOR,
                BlsScalar::from(123_456_789u64),
            ] {
                assert_eq!(
                    domain.evaluate_first_lagrange_coefficient(tau),
                    domain.evaluate_all_lagrange_coefficients(tau)[0],
                );
            }
        }
    }

    #[test]
    fn linear_coset_evaluations_match_closed_form() {
        let domain = EvaluationDomain::new(1 << 8).unwrap();
        let evaluations =
            domain.coset_fft(&[BlsScalar::zero(), BlsScalar::one()]);

        assert!(
            domain.matches_linear_poly_over_coset(evaluations.iter().copied())
        );
        for (i, evaluation) in evaluations.iter().enumerate() {
            let expected =
                GENERATOR * domain.group_gen.pow(&[i as u64, 0, 0, 0]);
            assert_eq!(*evaluation, expected);
        }
        let mut incorrect = evaluations.clone();
        incorrect[0] = incorrect[1];
        assert!(
            !domain.matches_linear_poly_over_coset(incorrect.iter().copied())
        );
        assert!(!domain.matches_linear_poly_over_coset(
            evaluations[..255].iter().copied()
        ));
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
            evaluations.iter().copied(),
        ));
        assert!(!domain.matches_vanishing_poly_over_coset(
            domain.size() as u64 + 1,
            evaluations.iter().copied(),
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
