// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A polynomial represented in evaluations form over a domain of size 2^n.

use alloc::vec::Vec;
use core::ops::{
    Add, AddAssign, DivAssign, Index, Mul, MulAssign, Sub, SubAssign,
};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Serialize,
    ser::{ScratchSpace, Serializer},
    validation::ArchiveContext,
};

use super::domain::EvaluationDomain;
use super::polynomial::Polynomial;
#[cfg(feature = "rkyv-impl")]
use crate::archive::{
    InvalidArchive, check_fields, scalars_are_canonical, unarchive,
};
use crate::error::Error;

/// Stores a polynomial in evaluation form together with its domain.
///
/// Keeping the domain makes the value self-contained: arithmetic operations
/// can reject incompatible evaluation sets, interpolation needs no external
/// parameter, and both byte encodings can round-trip an `Evaluations` value
/// independently.
#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace"))
)]
pub(crate) struct Evaluations {
    /// The evaluations of a polynomial over the domain `D`
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) evals: Vec<BlsScalar>,
    #[doc(hidden)]
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    domain: EvaluationDomain,
}

// Like `Evaluations::from_slice`, require canonical evaluations over the
// canonical domain of their size.
#[cfg(feature = "rkyv-impl")]
impl<C> CheckBytes<C> for ArchivedEvaluations
where
    C: ArchiveContext + ?Sized,
    C::Error: bytecheck::Error,
{
    type Error = InvalidArchive;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        check_fields!(value, context, evals, domain);
        let archived = unsafe { &*value };
        let domain = unarchive::<EvaluationDomain>(&archived.domain);
        let valid = usize::try_from(domain.size).is_ok_and(|size| {
            size.is_power_of_two()
                && archived.evals.len() == size
                && EvaluationDomain::new(size).is_ok_and(|new| new == domain)
        });
        if !valid || !scalars_are_canonical(&archived.evals) {
            return Err(InvalidArchive);
        }
        Ok(archived)
    }
}

impl Evaluations {
    /// Given an `Evaluations` struct, return it in it's byte representation.
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            EvaluationDomain::SIZE + self.evals.len() * BlsScalar::SIZE,
        );
        bytes.extend_from_slice(&self.domain.to_bytes());
        for scalar in &self.evals {
            bytes.extend_from_slice(&scalar.to_bytes());
        }

        bytes
    }

    /// Generate an `Evaluations` struct from a slice of bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Evaluations, Error> {
        let mut buffer = bytes;
        let domain = EvaluationDomain::from_reader(&mut buffer)?;
        let domain_size = usize::try_from(domain.size)
            .map_err(|_| dusk_bytes::Error::InvalidData)?;

        // Domains are serialized in full. Reconstruct the canonical domain so
        // malformed parameters cannot enter arithmetic through this path.
        if domain_size.checked_next_power_of_two() != Some(domain_size)
            || EvaluationDomain::new(domain_size)? != domain
        {
            return Err(dusk_bytes::Error::InvalidData.into());
        }

        let evaluations_size = domain_size
            .checked_mul(BlsScalar::SIZE)
            .ok_or(dusk_bytes::Error::InvalidData)?;
        if buffer.len() != evaluations_size {
            return Err(dusk_bytes::Error::InvalidData.into());
        }

        let evals = buffer
            .chunks(BlsScalar::SIZE)
            .map(BlsScalar::from_slice)
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

    /// Return the evaluation domain.
    pub(crate) const fn domain(&self) -> EvaluationDomain {
        self.domain
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

impl<'a> Mul<&'a Evaluations> for &Evaluations {
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

impl<'a> Add<&'a Evaluations> for &Evaluations {
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

impl<'a> Sub<&'a Evaluations> for &Evaluations {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fft::domain::EvaluationDomain;
    use crate::fft::polynomial::Polynomial;

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn archived_evaluations_require_their_canonical_domain() {
        let domain = EvaluationDomain::new(4).unwrap();
        let evaluations =
            Evaluations::from_vec_and_domain(vec![BlsScalar::one(); 4], domain);
        let bytes = rkyv::to_bytes::<_, 256>(&evaluations).unwrap();
        let decoded = rkyv::from_bytes::<Evaluations>(&bytes).unwrap();
        assert_eq!(decoded, evaluations);

        let archived = unsafe { rkyv::archived_root::<Evaluations>(&bytes) };
        let offset =
            |field: *const u8| field as usize - bytes.as_ptr() as usize;
        let size = offset(core::ptr::addr_of!(archived.domain.size).cast());
        let group_gen =
            offset(core::ptr::addr_of!(archived.domain.group_gen).cast());
        let one: Vec<u8> = BlsScalar::one()
            .internal_repr()
            .iter()
            .flat_map(|limb| limb.to_le_bytes())
            .collect();

        // A size that disagrees with the evaluations, and a domain that is
        // not the canonical one of its size.
        for (at, value) in [(size, &8u64.to_le_bytes()[..]), (group_gen, &one)]
        {
            let mut bytes = bytes.clone();
            bytes[at..at + value.len()].copy_from_slice(value);
            assert!(rkyv::check_archived_root::<Evaluations>(&bytes).is_err());
        }
    }

    #[test]
    fn evaluations_var_bytes_roundtrip() {
        let poly = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(1u64),
            BlsScalar::from(2u64),
            BlsScalar::from(3u64),
            BlsScalar::from(4u64),
        ]);

        let domain = EvaluationDomain::new(poly.len())
            .expect("domain construction should succeed");
        let evals = domain.fft(&poly);

        let evaluations = Evaluations::from_vec_and_domain(evals, domain);
        let bytes = evaluations.to_var_bytes();

        let decoded = Evaluations::from_slice(&bytes)
            .expect("decoding evaluations should succeed");
        assert_eq!(evaluations, decoded);
    }

    #[test]
    fn evaluations_reject_mismatched_serialized_lengths() {
        let domain = EvaluationDomain::new(4)
            .expect("domain construction should succeed");
        let evaluations = Evaluations::from_vec_and_domain(
            vec![BlsScalar::from(1u64); domain.size()],
            domain,
        );
        let bytes = evaluations.to_var_bytes();

        let truncated = &bytes[..bytes.len() - BlsScalar::SIZE];
        assert!(matches!(
            Evaluations::from_slice(truncated),
            Err(Error::BytesError(dusk_bytes::Error::InvalidData))
        ));

        let mut extended = bytes;
        extended.extend_from_slice(&BlsScalar::from(2u64).to_bytes());
        assert!(matches!(
            Evaluations::from_slice(&extended),
            Err(Error::BytesError(dusk_bytes::Error::InvalidData))
        ));
    }

    #[test]
    fn evaluations_reject_malformed_serialized_domain() {
        let domain = EvaluationDomain::new(4)
            .expect("domain construction should succeed");
        let evaluations = Evaluations::from_vec_and_domain(
            vec![BlsScalar::from(1u64); domain.size()],
            domain,
        );
        let mut bytes = evaluations.to_var_bytes();

        // Keep the serialized size (and therefore the evaluation count)
        // intact, but make the domain parameters internally inconsistent.
        bytes[u64::SIZE..u64::SIZE + u32::SIZE]
            .copy_from_slice(&0u32.to_bytes());

        assert!(matches!(
            Evaluations::from_slice(&bytes),
            Err(Error::BytesError(dusk_bytes::Error::InvalidData))
        ));
    }

    #[test]
    fn evaluations_interpolate_roundtrip() {
        let poly = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(7u64),
            BlsScalar::from(0u64),
            BlsScalar::from(5u64),
        ]);

        let domain = EvaluationDomain::new(poly.len())
            .expect("domain construction should succeed");
        let evals = domain.fft(&poly);
        let evaluations = Evaluations::from_vec_and_domain(evals, domain);

        let recovered = evaluations.clone().interpolate();
        assert_eq!(recovered, poly);
    }

    #[test]
    fn evaluations_arithmetic_is_element_wise() {
        let domain = EvaluationDomain::new(4)
            .expect("domain construction should succeed");

        let a = Evaluations::from_vec_and_domain(
            vec![
                BlsScalar::from(1u64),
                BlsScalar::from(2u64),
                BlsScalar::from(3u64),
                BlsScalar::from(4u64),
            ],
            domain,
        );
        let b = Evaluations::from_vec_and_domain(
            vec![
                BlsScalar::from(5u64),
                BlsScalar::from(6u64),
                BlsScalar::from(7u64),
                BlsScalar::from(8u64),
            ],
            domain,
        );

        // Indexing
        assert_eq!(a[2], BlsScalar::from(3u64));

        let add = &a + &b;
        assert_eq!(
            add.evals,
            vec![
                BlsScalar::from(6u64),
                BlsScalar::from(8u64),
                BlsScalar::from(10u64),
                BlsScalar::from(12u64)
            ]
        );

        let sub = &b - &a;
        assert_eq!(
            sub.evals,
            vec![
                BlsScalar::from(4u64),
                BlsScalar::from(4u64),
                BlsScalar::from(4u64),
                BlsScalar::from(4u64)
            ]
        );

        let mul = &a * &b;
        assert_eq!(
            mul.evals,
            vec![
                BlsScalar::from(5u64),
                BlsScalar::from(12u64),
                BlsScalar::from(21u64),
                BlsScalar::from(32u64)
            ]
        );

        let mut div = b.clone();
        div /= &a;
        assert_eq!(div.evals[0], BlsScalar::from(5u64));
        assert_eq!(div.evals[1], BlsScalar::from(3u64));
    }

    #[test]
    #[should_panic(expected = "domains are unequal")]
    fn operations_panic_on_domain_mismatch() {
        let domain_a = EvaluationDomain::new(4).unwrap();
        let domain_b = EvaluationDomain::new(8).unwrap();

        let a = Evaluations::from_vec_and_domain(
            vec![BlsScalar::one(); domain_a.size()],
            domain_a,
        );
        let b = Evaluations::from_vec_and_domain(
            vec![BlsScalar::one(); domain_b.size()],
            domain_b,
        );

        let _ = &a + &b;
    }
}
