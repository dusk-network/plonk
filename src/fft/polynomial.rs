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
use crate::util;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Deref, DerefMut, Mul, Neg, Sub, SubAssign};
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};

#[derive(Debug, Eq, PartialEq, Clone)]
/// Represents a polynomial in coeffiient form.
pub(crate) struct Polynomial {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    pub(crate) coeffs: Vec<BlsScalar>,
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
    pub(crate) fn from_coefficients_slice(coeffs: &[BlsScalar]) -> Self {
        Self::from_coefficients_vec(coeffs.to_vec())
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
        if self.is_zero() {
            return BlsScalar::zero();
        }

        // Compute powers of points
        let powers = util::powers_of(point, self.len());

        let p_evals: Vec<_> = self
            .iter()
            .zip(powers.into_iter())
            .map(|(c, p)| p * c)
            .collect();
        let mut sum = BlsScalar::zero();
        for eval in p_evals.into_iter() {
            sum += &eval;
        }
        sum
    }

    /// Given a [`Polynomial`], return it in it's bytes representation
    /// coefficient by coefficient.
    pub fn to_var_bytes(&self) -> Vec<u8> {
        self.coeffs
            .iter()
            .map(|item| item.to_bytes().to_vec())
            .flatten()
            .collect()
    }

    /// Generate a Polynomial from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Polynomial, Error> {
        let coeffs = bytes
            .chunks(BlsScalar::SIZE)
            .map(|chunk| BlsScalar::from_slice(chunk))
            .collect::<Result<Vec<BlsScalar>, dusk_bytes::Error>>()?;

        Ok(Polynomial { coeffs })
    }
}

use core::iter::Sum;

impl Sum for Polynomial {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        let sum: Polynomial = iter.fold(Polynomial::zero(), |mut res, val| {
            res = &res + &val;
            res
        });
        sum
    }
}

impl<'a, 'b> Add<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    fn add(self, other: &'a Polynomial) -> Polynomial {
        let mut result = if self.is_zero() {
            other.clone()
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            for (a, b) in result.coeffs.iter_mut().zip(&other.coeffs) {
                *a += b
            }
            result
        } else {
            let mut result = other.clone();
            for (a, b) in result.coeffs.iter_mut().zip(&self.coeffs) {
                *a += b
            }
            result
        };
        result.truncate_leading_zeros();
        result
    }
}

impl<'a, 'b> AddAssign<&'a Polynomial> for Polynomial {
    fn add_assign(&mut self, other: &'a Polynomial) {
        if self.is_zero() {
            self.coeffs.truncate(0);
            self.coeffs.extend_from_slice(&other.coeffs);
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a += b
            }
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a += b
            }
            self.truncate_leading_zeros();
        }
    }
}

impl<'a, 'b> AddAssign<(BlsScalar, &'a Polynomial)> for Polynomial {
    fn add_assign(&mut self, (f, other): (BlsScalar, &'a Polynomial)) {
        if self.is_zero() {
            self.coeffs.truncate(0);
            self.coeffs.extend_from_slice(&other.coeffs);
            self.coeffs.iter_mut().for_each(|c| *c *= &f);
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a += &(f * b);
            }
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a += &(f * b);
            }
            self.truncate_leading_zeros();
        }
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
        let mut result = if self.is_zero() {
            let mut result = other.clone();
            for coeff in &mut result.coeffs {
                *coeff = -(*coeff);
            }
            result
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            for (a, b) in result.coeffs.iter_mut().zip(&other.coeffs) {
                *a -= b
            }
            result
        } else {
            let mut result = self.clone();
            result.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (a, b) in result.coeffs.iter_mut().zip(&other.coeffs) {
                *a -= b;
            }
            result
        };
        result.truncate_leading_zeros();
        result
    }
}

impl<'a, 'b> SubAssign<&'a Polynomial> for Polynomial {
    #[inline]
    fn sub_assign(&mut self, other: &'a Polynomial) {
        if self.is_zero() {
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (i, coeff) in other.coeffs.iter().enumerate() {
                self.coeffs[i] -= coeff;
            }
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a -= b
            }
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a -= b
            }
            // If the leading coefficient ends up being zero, pop it off.
            self.truncate_leading_zeros();
        }
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
        let mut quotient: Vec<BlsScalar> = Vec::with_capacity(self.degree());
        let mut k = BlsScalar::zero();

        // Reverse the results and use Ruffini's method to compute the quotient
        // The coefficients must be reversed as Ruffini's method
        // starts with the leading coefficient, while Polynomials
        // are stored in increasing order i.e. the leading coefficient is the
        // last element
        for coeff in self.coeffs.iter().rev() {
            let t = coeff + k;
            quotient.push(t);
            k = z * t;
        }

        // Pop off the last element, it is the remainder term
        // For PLONK, we only care about perfect factors
        quotient.pop();

        // Reverse the results for storage in the Polynomial struct
        quotient.reverse();
        Polynomial::from_coefficients_vec(quotient)
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
            self_evals.interpolate()
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
        let mut result = self.clone();
        if constant == &BlsScalar::zero() {
            return result;
        }

        result[0] += constant;
        result
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
            let mut random_coeffs = Vec::with_capacity(d + 1);
            for _ in 0..=d {
                random_coeffs.push(util::random_scalar(&mut rng));
            }
            Self::from_coefficients_vec(random_coeffs)
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
