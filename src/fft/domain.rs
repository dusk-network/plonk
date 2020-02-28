//! This module contains an `EvaluationDomain` abstraction for
//! performing various kinds of polynomial arithmetic on top of
//! the scalar field.
//!
//! In pairing-based SNARKs like GM17, we need to calculate
//! a quotient polynomial over a target polynomial with roots
//! at distinct points associated with each constraint of the
//! constraint system. In order to be efficient, we choose these
//! roots to be the powers of a 2^n root of unity in the field.
//! This allows us to perform polynomial operations in O(n)
//! by performing an O(n log n) FFT over such a domain.

use core::fmt;
use new_bls12_381::Scalar;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::ops::MulAssign;

/// Defines a domain over which finite field (I)FFTs can be performed. Works
/// only for fields that have a large multiplicative subgroup of size that is
/// a power-of-2.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct EvaluationDomain {
    /// The size of the domain.
    pub size: u64,
    /// `log_2(self.size)`.
    pub log_size_of_group: u32,
    /// Size of the domain as a field element.
    pub size_as_field_element: Scalar,
    /// Inverse of the size in the field.
    pub size_inv: Scalar,
    /// A generator of the subgroup.
    pub group_gen: Scalar,
    /// Inverse of the generator of the subgroup.
    pub group_gen_inv: Scalar,
    /// Multiplicative generator of the finite field.
    pub generator_inv: Scalar,
}

impl fmt::Debug for EvaluationDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Multiplicative subgroup of size {}", self.size)
    }
}
// Constants for BLS
// XXX: These are defined in scalar.rs, but do not seem to be reachable
const TWO_ADICITY: u32 = 32;
const ROOT_OF_UNITY: Scalar = Scalar::from_raw([
    0xb9b58d8c5f0e466a,
    0x5b1b4c801819d7ec,
    0x0af53ae352a31e64,
    0x5bf3adda19e9b27b,
]);
const GENERATOR: Scalar = Scalar::from_raw([7, 0, 0, 0]);

impl EvaluationDomain {
    /// Construct a domain that is large enough for evaluations of a polynomial
    /// having `num_coeffs` coefficients.
    pub fn new(num_coeffs: usize) -> Option<Self> {
        // Compute the size of our evaluation domain
        let size = num_coeffs.next_power_of_two() as u64;
        let log_size_of_group = size.trailing_zeros();

        if log_size_of_group >= TWO_ADICITY {
            return None;
        }

        // Compute the generator for the multiplicative subgroup.
        // It should be 2^(log_size_of_group) root of unity.
        let mut group_gen = ROOT_OF_UNITY;
        for _ in log_size_of_group..TWO_ADICITY {
            group_gen = group_gen.square();
        }
        let size_as_field_element = Scalar::from(size);
        let size_inv = size_as_field_element.invert().unwrap();

        Some(EvaluationDomain {
            size,
            log_size_of_group,
            size_as_field_element,
            size_inv,
            group_gen,
            group_gen_inv: group_gen.invert().unwrap(),
            generator_inv: GENERATOR.invert().unwrap(),
        })
    }
    /// Return the size of a domain that is large enough for evaluations of a
    /// polynomial having `num_coeffs` coefficients.
    pub fn compute_size_of_domain(num_coeffs: usize) -> Option<usize> {
        let size = num_coeffs.next_power_of_two();
        if size.trailing_zeros() < TWO_ADICITY {
            Some(size)
        } else {
            None
        }
    }

    /// Return the size of `self`.
    pub fn size(&self) -> usize {
        self.size as usize
    }

    /// Compute a FFT.
    pub fn fft(&self, coeffs: &[Scalar]) -> Vec<Scalar> {
        let mut coeffs = coeffs.to_vec();
        self.fft_in_place(&mut coeffs);
        coeffs
    }

    /// Compute a FFT, modifying the vector in place.
    pub fn fft_in_place(&self, coeffs: &mut Vec<Scalar>) {
        coeffs.resize(self.size(), Scalar::zero());
        best_fft(coeffs, self.group_gen, self.log_size_of_group)
    }

    /// Compute a IFFT.
    pub fn ifft(&self, evals: &[Scalar]) -> Vec<Scalar> {
        let mut evals = evals.to_vec();
        self.ifft_in_place(&mut evals);
        evals
    }

    /// Compute a IFFT, modifying the vector in place.
    #[inline]
    pub fn ifft_in_place(&self, evals: &mut Vec<Scalar>) {
        evals.resize(self.size(), Scalar::zero());
        best_fft(evals, self.group_gen_inv, self.log_size_of_group);
        // cfg_iter_mut!(evals).for_each(|val| *val *= &self.size_inv);
        evals.par_iter_mut().for_each(|val| *val *= &self.size_inv);
    }

    fn distribute_powers(coeffs: &mut [Scalar], g: Scalar) {
        let mut pow = Scalar::one();
        coeffs.iter_mut().for_each(|c| {
            *c *= &pow;
            pow *= &g
        })
    }

    /// Compute a FFT over a coset of the domain.
    pub fn coset_fft(&self, coeffs: &[Scalar]) -> Vec<Scalar> {
        let mut coeffs = coeffs.to_vec();
        self.coset_fft_in_place(&mut coeffs);
        coeffs
    }

    /// Compute a FFT over a coset of the domain, modifying the input vector
    /// in place.
    pub fn coset_fft_in_place(&self, coeffs: &mut Vec<Scalar>) {
        Self::distribute_powers(coeffs, GENERATOR);
        self.fft_in_place(coeffs);
    }

    /// Compute a IFFT over a coset of the domain.
    pub fn coset_ifft(&self, evals: &[Scalar]) -> Vec<Scalar> {
        let mut evals = evals.to_vec();
        self.coset_ifft_in_place(&mut evals);
        evals
    }

    /// Compute a IFFT over a coset of the domain, modifying the input vector in
    /// place.
    pub fn coset_ifft_in_place(&self, evals: &mut Vec<Scalar>) {
        self.ifft_in_place(evals);
        Self::distribute_powers(evals, self.generator_inv);
    }

    /// Evaluate all the lagrange polynomials defined by this domain at the
    /// point `tau`.
    pub fn evaluate_all_lagrange_coefficients(&self, tau: Scalar) -> Vec<Scalar> {
        // Evaluate all Lagrange polynomials
        let size = self.size as usize;
        let t_size = tau.pow(&[self.size, 0, 0, 0]);
        let one = Scalar::one();
        if t_size == Scalar::one() {
            let mut u = vec![Scalar::zero(); size];
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
            use crate::batch_inversion;

            let mut l = (t_size - &one) * &self.size_inv;
            let mut r = one;
            let mut u = vec![Scalar::zero(); size];
            let mut ls = vec![Scalar::zero(); size];
            for i in 0..size {
                u[i] = tau - &r;
                ls[i] = l;
                l *= &self.group_gen;
                r *= &self.group_gen;
            }

            batch_inversion(u.as_mut_slice());

            u.par_iter_mut().zip(ls).for_each(|(tau_minus_r, l)| {
                *tau_minus_r = l * *tau_minus_r;
            });

            u
        }
    }

    /// This evaluates the vanishing polynomial for this domain at tau.
    /// For multiplicative subgroups, this polynomial is `z(X) = X^self.size -
    /// 1`.
    pub fn evaluate_vanishing_polynomial(&self, tau: Scalar) -> Scalar {
        tau.pow(&[self.size, 0, 0, 0]) - &Scalar::one()
    }

    /// Return an iterator over the elements of the domain.
    pub fn elements(&self) -> Elements {
        Elements {
            cur_elem: Scalar::one(),
            cur_pow: 0,
            domain: *self,
        }
    }

    /// The target polynomial is the zero polynomial in our
    /// evaluation domain, so we must perform division over
    /// a coset.
    pub fn divide_by_vanishing_poly_on_coset_in_place(&self, evals: &mut [Scalar]) {
        let i = self
            .evaluate_vanishing_polynomial(GENERATOR)
            .invert()
            .unwrap();

        evals.par_iter_mut().for_each(|eval| *eval *= &i);
    }

    /// Given an index which assumes the first elements of this domain are the
    /// elements of another (sub)domain with size size_s,
    /// this returns the actual index into this domain.
    pub fn reindex_by_subdomain(&self, other: Self, index: usize) -> usize {
        assert!(self.size() >= other.size());
        // Let this subgroup be G, and the subgroup we're re-indexing by be S.
        // Since its a subgroup, the 0th element of S is at index 0 in G, the first
        // element of S is at index |G|/|S|, the second at 2*|G|/|S|, etc.
        // Thus for an index i that corresponds to S, the index in G is i*|G|/|S|
        let period = self.size() / other.size();
        if index < other.size() {
            index * period
        } else {
            // Let i now be the index of this element in G \ S
            // Let x be the number of elements in G \ S, for every element in S. Then x =
            // (|G|/|S| - 1). At index i in G \ S, the number of elements in S
            // that appear before the index in G to which i corresponds to, is
            // floor(i / x) + 1. The +1 is because index 0 of G is S_0, so the
            // position is offset by at least one. The floor(i / x) term is
            // because after x elements in G \ S, there is one more element from S
            // that will have appeared in G.
            let i = index - other.size();
            let x = period - 1;
            i + (i / x) + 1
        }
    }

    /// Perform O(n) multiplication of two polynomials that are presented by
    /// their evaluations in the domain.
    /// Returns the evaluations of the product over the domain.
    ///
    /// Assumes that the domain is large enough to allow for successful
    /// interpolation after multiplication.
    #[must_use]
    pub fn mul_polynomials_in_evaluation_domain(
        &self,
        self_evals: &[Scalar],
        other_evals: &[Scalar],
    ) -> Vec<Scalar> {
        assert_eq!(self_evals.len(), other_evals.len());
        let mut result = self_evals.to_vec();

        result
            .par_iter_mut()
            .zip(other_evals)
            .for_each(|(a, b)| *a *= b);

        result
    }
}

#[cfg(feature = "parallel")]
fn best_fft(a: &mut [Scalar], omega: Scalar, log_n: u32) {
    fn log2_floor(num: usize) -> u32 {
        assert!(num > 0);
        let mut pow = 0;
        while (1 << (pow + 1)) <= num {
            pow += 1;
        }
        pow
    }

    let num_cpus = rayon::current_num_threads();
    let log_cpus = log2_floor(num_cpus);
    if log_n <= log_cpus {
        serial_fft(a, omega, log_n);
    } else {
        parallel_fft(a, omega, log_n, log_cpus);
    }
}

#[cfg(not(feature = "parallel"))]
fn best_fft(a: &mut [Scalar], omega: Scalar, log_n: u32) {
    serial_fft(a, omega, log_n)
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

pub(crate) fn serial_fft(a: &mut [Scalar], omega: Scalar, log_n: u32) {
    let n = a.len() as u32;
    assert_eq!(n, 1 << log_n);

    for k in 0..n {
        let rk = bitreverse(k, log_n);
        if k < rk {
            a.swap(rk as usize, k as usize);
        }
    }

    let mut m = 1;
    for _ in 0..log_n {
        let w_m = omega.pow(&[(n / (2 * m)) as u64, 0, 0, 0]);

        let mut k = 0;
        while k < n {
            let mut w = Scalar::one();
            for j in 0..m {
                let mut t = a[(k + j + m) as usize];
                t *= &w;
                let mut tmp = a[(k + j) as usize];
                tmp -= &t;
                a[(k + j + m) as usize] = tmp;
                a[(k + j) as usize] += &t;
                w.mul_assign(&w_m);
            }

            k += 2 * m;
        }

        m *= 2;
    }
}

#[cfg(feature = "parallel")]
pub(crate) fn parallel_fft(a: &mut [Scalar], omega: Scalar, log_n: u32, log_cpus: u32) {
    assert!(log_n >= log_cpus);

    let num_cpus = 1 << log_cpus;
    let log_new_n = log_n - log_cpus;
    let mut tmp = vec![vec![F::zero(); 1 << log_new_n]; num_cpus];
    let new_omega = omega.pow(&[num_cpus as u64]);

    tmp.par_iter_mut().enumerate().for_each(|(j, tmp)| {
        // Shuffle into a sub-FFT
        let omega_j = omega.pow(&[j as u64]);
        let omega_step = omega.pow(&[(j as u64) << log_new_n]);

        let mut elt = F::one();
        for i in 0..(1 << log_new_n) {
            for s in 0..num_cpus {
                let idx = (i + (s << log_new_n)) % (1 << log_n);
                let mut t = a[idx];
                t *= &elt;
                tmp[i] += &t;
                elt *= &omega_step;
            }
            elt *= &omega_j;
        }

        // Perform sub-FFT
        serial_fft(tmp, new_omega, log_new_n);
    });

    let mask = (1 << log_cpus) - 1;
    a.iter_mut()
        .enumerate()
        .for_each(|(i, a)| *a = tmp[i & mask][i >> log_cpus]);
}

/// An iterator over the elements of the domain.
pub struct Elements {
    cur_elem: Scalar,
    cur_pow: u64,
    domain: EvaluationDomain,
}

impl Iterator for Elements {
    type Item = Scalar;
    fn next(&mut self) -> Option<Scalar> {
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

#[cfg(test)]
mod tests {
    use super::EvaluationDomain;
    use new_bls12_381::Scalar;
    use rand::Rng;

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
}
