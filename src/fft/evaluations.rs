// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A polynomial represented in evaluations form over a domain of size 2^n.

use super::domain::EvaluationDomain;
use super::polynomial::Polynomial;
use crate::error::Error;
use alloc::vec::Vec;
use core::ops::{
    Add, AddAssign, DivAssign, Index, Mul, MulAssign, Sub, SubAssign,
};
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};

/// Stores a polynomial in evaluation form.
#[derive(PartialEq, Eq, Debug, Clone)]
pub(crate) struct Evaluations {
    /// The evaluations of a polynomial over the domain `D`
    pub(crate) evals: Vec<BlsScalar>,
    #[doc(hidden)]
    // FIXME: We should probably remove that and should be an external object.
    domain: EvaluationDomain,
}

impl Evaluations {
    /// Given an `Evaluations` struct, return it in it's byte representation.
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.domain.to_bytes().to_vec();
        bytes.extend(
            self.evals
                .iter()
                .map(|scalar| scalar.to_bytes().to_vec())
                .flatten(),
        );

        bytes
    }

    /// Generate an `Evaluations` struct from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Evaluations, Error> {
        let mut buffer = bytes;
        let domain = EvaluationDomain::from_reader(&mut buffer)?;
        let evals = buffer
            .chunks(BlsScalar::SIZE)
            .map(|chunk| BlsScalar::from_slice(chunk))
            .collect::<Result<Vec<BlsScalar>, dusk_bytes::Error>>()?;
        Ok(Evaluations::from_vec_and_domain(evals, domain))
    }

    /// Construct `Self` from evaluations and a domain.
    pub(crate) const fn from_vec_and_domain(
        evals: Vec<BlsScalar>,
        domain: EvaluationDomain,
    ) -> Self {
        Self { evals, domain }
    }

    /// Interpolate a polynomial from a list of evaluations
    pub(crate) fn interpolate(self) -> Polynomial {
        let Self { mut evals, domain } = self;
        domain.ifft_in_place(&mut evals);
        Polynomial::from_coefficients_vec(evals)
    }
}

impl Index<usize> for Evaluations {
    type Output = BlsScalar;

    fn index(&self, index: usize) -> &BlsScalar {
        &self.evals[index]
    }
}

impl<'a, 'b> Mul<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn mul(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result *= other;
        result
    }
}

impl<'a> MulAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn mul_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a *= b);
    }
}

impl<'a, 'b> Add<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn add(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result += other;
        result
    }
}

impl<'a> AddAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn add_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a += b);
    }
}

impl<'a, 'b> Sub<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn sub(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result -= other;
        result
    }
}

impl<'a> SubAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn sub_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a -= b);
    }
}

impl<'a> DivAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn div_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a *= b.invert().unwrap());
    }
}
