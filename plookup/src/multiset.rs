// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::PlookupErrors;
use dusk_plonk::bls12_381::BlsScalar;
use dusk_plonk::fft::{EvaluationDomain, Polynomial};
use std::ops::{Add, Mul};

/// MultiSet is struct containing vectors of scalars, which
/// individually represents either a wire value or an index
/// of a PlookUp table
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MultiSet(Vec<BlsScalar>);

impl MultiSet {
    /// Creates an empty vector with a multiset wrapper around it
    pub fn new() -> MultiSet {
        MultiSet(vec![])
    }

    /// Extends the length of the multiset to 2^n elements
    /// The 2^n will be the size of the arithmetic circuit
    /// we are constructing
    pub fn pad(&mut self, n: u32) {
        let new_length = 2u64.pow(n);
        let diff = new_length - self.len() as u64;
        self.0.extend(vec![BlsScalar::zero(); diff as usize]);
    }

    /// Pushes chosen value onto the end of the Multiset
    pub fn push(&mut self, value: BlsScalar) {
        self.0.push(value)
    }

    /// Fetches last element in MultiSet.
    /// Returns None if there are no elements in the MultiSet.
    pub fn last(&self) -> Option<&BlsScalar> {
        self.0.last()
    }

    fn from_slice(slice: &[BlsScalar]) -> MultiSet {
        MultiSet(slice.to_vec())
    }

    /// Returns the cardinality of the multiset
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the position of the element in the Multiset.
    /// Returns None if the element is not found.
    pub fn position(&self, element: &BlsScalar) -> Option<usize> {
        self.0.iter().position(|&x| x == *element)
    }

    /// Concatenates and sorts two Multisets together.
    /// From the Plookup paper, if we have t: {1,2,4,3}
    /// and f: {2,3,4,1}.
    /// We first check if all elements of f exist in t
    /// Then we combine the multisets together and sort
    /// their elements together. The final MultiSet will
    /// look as follows, s: {1,1,2,2,3,3,4,4}
    pub fn sort_and_index(&self, f: &MultiSet) -> Result<MultiSet, PlookupErrors> {
        let mut s: Vec<BlsScalar> = Vec::with_capacity(self.0.len() + f.0.len());
        let mut s = self.clone();
        for element in f.0.iter() {
            let index = s
                .position(element)
                .ok_or(PlookupErrors::ElementNotIndexed)?;
            s.0.insert(index, *element);
        }

        Ok(s)
    }

    /// Checks whether self is a subset of other
    pub fn is_subset_of(&self, other: &MultiSet) -> bool {
        let mut is_subset = true;

        for x in self.0.iter() {
            is_subset = other.contains(x);
            if is_subset == false {
                break;
            }
        }

        is_subset
    }

    /// Checks if an element is in the MultiSet
    pub fn contains(&self, entry: &BlsScalar) -> bool {
        self.0.contains(entry)
    }

    /// Splits a multiset into halves as specified by the paper
    /// If s = [1,2,3,4,5,6,7], we can deduce n using |s| = 2 * n + 1 = 7
    /// n is therefore 3
    /// We split s into two MultiSets of size n+1 each
    /// s_0 = [1,2,3,4] ,|s_0| = n+1 = 4
    /// s_1 = [4,5,6,7] , |s_1| = n+1 = 4
    /// Notice that the last element of the first half equals the first element in the second half
    /// This is specified in the paper
    pub fn halve(&self) -> (MultiSet, MultiSet) {
        let length = self.0.len();

        let first_half = MultiSet::from_slice(&self.0[0..=length / 2]);
        let second_half = MultiSet::from_slice(&self.0[length / 2..]);

        (first_half, second_half)
    }

    /// Treats each element in the multiset as evaluation points
    /// Computes IFFT of the set of evaluation points
    /// and returns the coefficients as a Polynomial data structure
    pub fn to_polynomial(&self, domain: &EvaluationDomain) -> Polynomial {
        Polynomial::from_coefficients_vec(domain.ifft(&self.0))
    }

    /// Turn three multisets into a single multiset using
    /// a random challenge, Alpha. Alpha is dervived by hashing
    /// the transcript.
    /// The function iterates over the given sets and mutiplies by alpha:
    /// a + (b * alpha) + (c * alpha^2)  
    pub fn compress_three_arity(multisets: [&MultiSet; 3], alpha: BlsScalar) -> MultiSet {
        MultiSet(
            multisets[0]
                .0
                .iter()
                .zip(multisets[1].0.iter())
                .zip(multisets[2].0.iter())
                .map(|((a, b), c)| a + b * alpha + c * alpha.square())
                .collect::<Vec<BlsScalar>>(),
        )
    }

    /// Turn four multisets into a single multiset using
    /// a random challenge, Alpha. Alpha is dervived by hashing
    /// the transcript.
    /// The function iterates over the given sets and mutiplies by alpha:
    /// a + (b * alpha) + (c * alpha^2) + (d * alpha^3)  
    pub fn compress_four_arity(multisets: [&MultiSet; 4], alpha: BlsScalar) -> MultiSet {
        MultiSet(
            multisets[0]
                .0
                .iter()
                .zip(multisets[1].0.iter())
                .zip(multisets[2].0.iter())
                .zip(multisets[3].0.iter())
                .map(|(((a, b), c), d)| {
                    a + b * alpha + c * alpha.square() + d * alpha.pow(&[3u64, 0u64, 0u64, 0u64])
                })
                .collect::<Vec<BlsScalar>>(),
        )
    }
}

impl Add for MultiSet {
    type Output = MultiSet;

    fn add(self, other: MultiSet) -> Self::Output {
        let result = self
            .0
            .into_iter()
            .zip(other.0.iter())
            .map(|(x, y)| x + y)
            .collect();

        MultiSet(result)
    }
}

impl Mul for MultiSet {
    type Output = MultiSet;

    fn mul(self, other: MultiSet) -> Self::Output {
        let result = self
            .0
            .into_iter()
            .zip(other.0.iter())
            .map(|(x, y)| x * y)
            .collect();

        MultiSet(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use dusk_plonk::fft::{EvaluationDomain, Polynomial};

    #[test]
    fn test_halve() {
        let mut a = MultiSet::new();
        a.push(BlsScalar::from(14));
        a.push(BlsScalar::from(24));
        a.push(BlsScalar::from(34));
        a.push(BlsScalar::from(44));
        a.push(BlsScalar::from(54));
        a.push(BlsScalar::from(64));
        a.push(BlsScalar::from(74));

        let (h_1, h_2) = a.halve();
        assert_eq!(h_1.len(), 4);
        assert_eq!(h_2.len(), 4);

        assert_eq!(
            MultiSet(vec![
                BlsScalar::from(14),
                BlsScalar::from(24),
                BlsScalar::from(34),
                BlsScalar::from(44)
            ]),
            h_1
        );

        assert_eq!(
            MultiSet(vec![
                BlsScalar::from(44),
                BlsScalar::from(54),
                BlsScalar::from(64),
                BlsScalar::from(74)
            ]),
            h_2
        );

        // Last element in the first half should equal first element in the second half
        assert_eq!(h_1.0.last().unwrap(), &h_2.0[0])
    }

    #[test]
    fn test_to_polynomial() {

        let mut a = MultiSet::new();
        a.push(BlsScalar::from(1));
        a.push(BlsScalar::from(2));
        a.push(BlsScalar::from(3));
        a.push(BlsScalar::from(4));
        a.push(BlsScalar::from(5));
        a.push(BlsScalar::from(6));
        a.push(BlsScalar::from(7));

        let domain = EvaluationDomain::new(a.len() + 1).unwrap();
        let a_poly = a.to_polynomial(&domain);

        assert_eq!(a_poly.degree(), 7)
    }
    #[test]
    fn test_is_subset() {
        let mut a = MultiSet::new();
        a.push(BlsScalar::from(1));
        a.push(BlsScalar::from(2));
        a.push(BlsScalar::from(3));
        a.push(BlsScalar::from(4));
        a.push(BlsScalar::from(5));
        a.push(BlsScalar::from(6));
        a.push(BlsScalar::from(7));
        let mut b = MultiSet::new();
        b.push(BlsScalar::from(1));
        b.push(BlsScalar::from(2));
        let mut c = MultiSet::new();
        c.push(BlsScalar::from(100));

        assert!(b.is_subset_of(&a));
        assert!(!c.is_subset_of(&a));
    }
}