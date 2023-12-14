// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module contains an implementation of a polynomial in coefficient form
//! Where each coefficient is represented using a position in the underlying
//! vector.
use super::{EvaluationDomain, Evaluations};
use crate::error::Error;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Deref, DerefMut, Mul, Neg, Sub, SubAssign};
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

/// Represents a polynomial in coeffiient form.
#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct Polynomial {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    coeffs: Vec<BlsScalar>,
}

impl Deref for Polynomial {
    type Target = [BlsScalar];

    fn deref(&self) -> &[BlsScalar] {
        &self.coeffs
    }
}

impl DerefMut for Polynomial {
    fn deref_mut(&mut self) -> &mut [BlsScalar] {
        &mut self.coeffs
    }
}

impl IntoIterator for Polynomial {
    type Item = BlsScalar;
    type IntoIter = <Vec<BlsScalar> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.coeffs.into_iter()
    }
}

impl Polynomial {
    /// Returns the zero polynomial.
    pub(crate) const fn zero() -> Self {
        Self { coeffs: Vec::new() }
    }

    /// Checks if the given polynomial is zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.coeffs.is_empty()
            || self.coeffs.iter().all(|coeff| coeff == &BlsScalar::zero())
    }

    /// Constructs a new polynomial from a list of coefficients.
    ///
    /// # Panics
    /// When the length of the coeffs is zero.
    pub(crate) fn from_coefficients_vec(coeffs: Vec<BlsScalar>) -> Self {
        let mut result = Self { coeffs };
        // While there are zeros at the end of the coefficient vector, pop them
        // off.
        result.truncate_leading_zeros();
        // Check that either the coefficients vec is empty or that the last
        // coeff is non-zero.
        assert!(result
            .coeffs
            .last()
            .map_or(true, |coeff| coeff != &BlsScalar::zero()));

        result
    }

    /// Returns the degree of the [`Polynomial`].
    pub(crate) fn degree(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        assert!(self
            .coeffs
            .last()
            .map_or(false, |coeff| coeff != &BlsScalar::zero()));
        self.coeffs.len() - 1
    }

    fn truncate_leading_zeros(&mut self) {
        while self
            .coeffs
            .last()
            .map_or(false, |c| c == &BlsScalar::zero())
        {
            self.coeffs.pop();
        }
    }

    /// Evaluates a [`Polynomial`] at a given point in the field.
    pub(crate) fn evaluate(&self, point: &BlsScalar) -> BlsScalar {
        self.coeffs
            .iter()
            .rev()
            .fold(BlsScalar::zero(), |sum, coeff| sum * point + coeff)
    }

    /// Given a [`Polynomial`], return it in it's bytes representation
    /// coefficient by coefficient.
    pub fn to_var_bytes(&self) -> Vec<u8> {
        self.coeffs
            .iter()
            .flat_map(|item| item.to_bytes().to_vec())
            .collect()
    }

    /// Generate a Polynomial from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Polynomial, Error> {
        let coeffs = bytes
            .chunks(BlsScalar::SIZE)
            .map(BlsScalar::from_slice)
            .collect::<Result<Vec<BlsScalar>, dusk_bytes::Error>>()?;

        Ok(Polynomial { coeffs })
    }

    /// Returns an iterator over the polynomial coefficients.
    fn iter(&self) -> impl Iterator<Item = &BlsScalar> {
        self.coeffs.iter()
    }
}

use core::iter;
use core::iter::Sum;

impl Sum for Polynomial {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        iter.fold(Polynomial::zero(), |res, val| &res + &val)
    }
}

impl<'a, 'b> Add<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    fn add(self, other: &'a Polynomial) -> Polynomial {
        let zero = BlsScalar::zero();
        let (left, right) = if self.degree() >= other.degree() {
            (
                self.coeffs.iter(),
                other.coeffs.iter().chain(iter::repeat(&zero)),
            )
        } else {
            (
                other.coeffs.iter(),
                self.coeffs.iter().chain(iter::repeat(&zero)),
            )
        };
        Polynomial::from_coefficients_vec(
            left.zip(right).map(|(a, b)| *a + *b).collect::<Vec<_>>(),
        )
    }
}

impl<'a> AddAssign<&'a Polynomial> for Polynomial {
    fn add_assign(&mut self, other: &'a Polynomial) {
        if self.degree() >= other.degree() {
            self.coeffs
                .iter_mut()
                .zip(other.coeffs.iter())
                .for_each(|(a, b)| *a += b);
        } else {
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            self.coeffs
                .iter_mut()
                .zip(other.coeffs.iter())
                .for_each(|(a, b)| *a += b);
        };
        self.truncate_leading_zeros()
    }
}

impl<'a> AddAssign<(BlsScalar, &'a Polynomial)> for Polynomial {
    fn add_assign(&mut self, (f, other): (BlsScalar, &'a Polynomial)) {
        if self.degree() > other.degree() {
            self.coeffs
                .iter_mut()
                .zip(other.coeffs.iter())
                .for_each(|(a, b)| *a += b * f);
        } else {
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            self.coeffs
                .iter_mut()
                .zip(other.coeffs.iter())
                .for_each(|(a, b)| *a += b * f);
        };
        self.truncate_leading_zeros()
    }
}

impl Neg for Polynomial {
    type Output = Polynomial;

    #[inline]
    fn neg(mut self) -> Polynomial {
        for coeff in &mut self.coeffs {
            *coeff = -*coeff;
        }
        self
    }
}

impl<'a, 'b> Sub<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn sub(self, other: &'a Polynomial) -> Polynomial {
        let zero = BlsScalar::zero();
        let (left, right) = if self.degree() >= other.degree() {
            (
                self.coeffs.iter(),
                other.coeffs.iter().chain(iter::repeat(&zero)),
            )
        } else {
            (
                other.coeffs.iter(),
                self.coeffs.iter().chain(iter::repeat(&zero)),
            )
        };
        Polynomial::from_coefficients_vec(
            left.zip(right).map(|(a, b)| *a - *b).collect::<Vec<_>>(),
        )
    }
}

impl<'a> SubAssign<&'a Polynomial> for Polynomial {
    #[inline]
    fn sub_assign(&mut self, other: &'a Polynomial) {
        if self.degree() >= other.degree() {
            self.coeffs
                .iter_mut()
                .zip(other.coeffs.iter())
                .for_each(|(a, b)| *a -= b);
        } else {
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            self.coeffs
                .iter_mut()
                .zip(other.coeffs.iter())
                .for_each(|(a, b)| *a -= b);
        };
        self.truncate_leading_zeros()
    }
}

impl Polynomial {
    #[allow(dead_code)]
    #[inline]
    fn leading_coefficient(&self) -> Option<&BlsScalar> {
        self.last()
    }

    #[allow(dead_code)]
    #[inline]
    fn iter_with_index(&self) -> Vec<(usize, BlsScalar)> {
        self.iter().cloned().enumerate().collect()
    }

    /// Divides a [`Polynomial`] by x-z using Ruffinis method.
    pub fn ruffini(&self, z: BlsScalar) -> Polynomial {
        let mut coeffs = self
            .coeffs
            .iter()
            .rev()
            .scan(BlsScalar::zero(), |w, coeff| {
                let tmp = *w + coeff;
                *w = tmp * z;
                Some(tmp)
            })
            .collect::<Vec<_>>();

        // Pop off the last element, it is the remainder term
        // For PLONK, we only care about perfect factors
        coeffs.pop();

        // Reverse the results for storage in the Polynomial struct
        coeffs.reverse();
        Polynomial::from_coefficients_vec(coeffs)
    }
}

/// Performs O(nlogn) multiplication of polynomials if F is smooth.
impl<'a, 'b> Mul<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn mul(self, other: &'a Polynomial) -> Polynomial {
        if self.is_zero() || other.is_zero() {
            Polynomial::zero()
        } else {
            let domain =
                EvaluationDomain::new(self.coeffs.len() + other.coeffs.len())
                    .expect("field is not smooth enough to construct domain");
            let mut self_evals = Evaluations::from_vec_and_domain(
                domain.fft(&self.coeffs),
                domain,
            );
            let other_evals = Evaluations::from_vec_and_domain(
                domain.fft(&other.coeffs),
                domain,
            );
            self_evals *= &other_evals;
            let Evaluations { mut evals, .. } = self_evals;
            domain.ifft_in_place(&mut evals);
            Polynomial::from_coefficients_vec(evals)
        }
    }
}

impl<'a, 'b> Mul<&'a BlsScalar> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn mul(self, constant: &'a BlsScalar) -> Polynomial {
        if self.is_zero() || (constant == &BlsScalar::zero()) {
            return Polynomial::zero();
        }
        let scaled_coeffs: Vec<_> =
            self.coeffs.iter().map(|coeff| coeff * constant).collect();
        Polynomial::from_coefficients_vec(scaled_coeffs)
    }
}

impl<'a, 'b> Add<&'a BlsScalar> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn add(self, constant: &'a BlsScalar) -> Polynomial {
        if self.is_zero() {
            return Polynomial::from_coefficients_vec(vec![*constant]);
        }
        self + constant
    }
}

impl<'a, 'b> Sub<&'a BlsScalar> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn sub(self, constant: &'a BlsScalar) -> Polynomial {
        let negated_constant = -constant;
        self + &negated_constant
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use ff::Field;
    use rand_core::{CryptoRng, RngCore};

    impl Polynomial {
        /// Outputs a polynomial of degree `d` where each coefficient is sampled
        /// uniformly at random from the field `F`.
        /// This is only implemented for test purposes for now but inside of a
        /// `impl` block since it's used across multiple files in the
        /// repo.
        pub(crate) fn rand<R: RngCore + CryptoRng>(
            d: usize,
            mut rng: &mut R,
        ) -> Self {
            Self::from_coefficients_vec(
                (0..=d).map(|_| BlsScalar::random(&mut rng)).collect(),
            )
        }
    }

    #[test]
    fn test_ruffini() {
        // X^2 + 4X + 4
        let quadratic = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(4),
            BlsScalar::from(4),
            BlsScalar::one(),
        ]);
        // Divides X^2 + 4X + 4 by X+2
        let quotient = quadratic.ruffini(-BlsScalar::from(2));
        // X+2
        let expected_quotient = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(2),
            BlsScalar::one(),
        ]);
        assert_eq!(quotient, expected_quotient);
    }

    #[test]
    fn test_ruffini_zero() {
        // Tests the two situations where zero can be added to Ruffini:
        // (1) Zero polynomial in the divided
        // (2) Zero as the constant term for the polynomial you are dividing by
        // In the first case, we should get zero as the quotient
        // In the second case, this is the same as dividing by X
        // (1)
        //
        // Zero polynomial
        let zero = Polynomial::zero();
        // Quotient is invariant under any argument we pass
        let quotient = zero.ruffini(-BlsScalar::from(2));
        assert_eq!(quotient, Polynomial::zero());
        // (2)
        //
        // X^2 + X
        let p = Polynomial::from_coefficients_vec(vec![
            BlsScalar::zero(),
            BlsScalar::one(),
            BlsScalar::one(),
        ]);
        // Divides X^2 + X by X
        let quotient = p.ruffini(BlsScalar::zero());
        // X + 1
        let expected_quotient = Polynomial::from_coefficients_vec(vec![
            BlsScalar::one(),
            BlsScalar::one(),
        ]);
        assert_eq!(quotient, expected_quotient);
    }
}
