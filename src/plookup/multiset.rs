// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::bls12_381::BlsScalar;
use crate::fft::{EvaluationDomain, Polynomial};
use crate::plookup::error::PlookupErrors;
use std::ops::{Add, Mul};

/// MultiSet is struct containing vectors of scalars, which
/// individually represents either a wire value or an index
/// of a PlookUp table
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MultiSet(pub Vec<BlsScalar>);

impl Default for MultiSet {
    fn default() -> Self {
        MultiSet::new()
    }
}

impl From<&[BlsScalar]> for MultiSet {
    fn from(slice: &[BlsScalar]) -> MultiSet {
        MultiSet(slice.to_vec())
    }
}

impl MultiSet {
    /// Creates an empty vector with a multiset wrapper around it
    pub fn new() -> MultiSet {
        MultiSet(vec![])
    }

    /// Extends the length of the multiset to 2^n elements
    /// The 2^n will be the size of the arithmetic circuit.
    /// This will extend the vectors to the size
    pub fn pad(&mut self, n: u32) {
        assert!(n.is_power_of_two());
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

    /// Returns the cardinality of the multiset
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether or not the multiset is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
    pub fn sorted_concat(&self, f: &MultiSet) -> Result<MultiSet, PlookupErrors> {
        let mut s = self.clone();
        s.0.reserve(f.0.len());
        for element in f.0.iter() {
            let index = s
                .position(element)
                .ok_or(PlookupErrors::ElementNotIndexed)?;
            s.0.insert(index, *element);
        }

        Ok(s)
    }

    /// Checks whether one mutltiset is a subset of another.
    /// This function will be used to check if the all elements
    /// in set f, from the paper, are contained inside t.
    pub fn contains_all(&self, other: &MultiSet) -> bool {
        other.0.iter().all(|item| self.contains(item))
    }

    /// Checks if an element is in the MultiSet
    pub fn contains(&self, entry: &BlsScalar) -> bool {
        self.0.contains(entry)
    }

    /// Splits a multiset into halves as specified by the paper
    /// The last element of the first half should be the same
    /// as the first element of the second half.
    /// Since a multiset can never have an even cardinality, we
    /// always split it in the way described above.
    pub fn halve(&self) -> (MultiSet, MultiSet) {
        let length = self.0.len();

        let first_half = MultiSet::from(&self.0[0..=length / 2]);
        let second_half = MultiSet::from(&self.0[length / 2..]);

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
    use crate::fft::EvaluationDomain;
    use crate::plookup::WitnessTable3Arity;

    #[test]
    fn test_halve() {
        let mut s = MultiSet::new();
        s.push(BlsScalar::from(0));
        s.push(BlsScalar::from(1));
        s.push(BlsScalar::from(2));
        s.push(BlsScalar::from(3));
        s.push(BlsScalar::from(4));
        s.push(BlsScalar::from(5));
        s.push(BlsScalar::from(6));

        let (h_1, h_2) = s.halve();
        assert_eq!(h_1.len(), 4);
        assert_eq!(h_2.len(), 4);

        let left_half = MultiSet(vec![
            BlsScalar::from(0),
            BlsScalar::from(1),
            BlsScalar::from(2),
            BlsScalar::from(3),
        ]);

        assert_eq!(left_half, h_1);

        let right_half = MultiSet(vec![
            BlsScalar::from(3),
            BlsScalar::from(4),
            BlsScalar::from(5),
            BlsScalar::from(6),
        ]);

        assert_eq!(right_half, h_2);

        // The last element of the first half should equal the first
        // element of the second half.
        assert_eq!(h_1.0.last().unwrap(), &h_2.0[0])
    }

    #[test]
    fn test_to_polynomial() {
        let mut s = MultiSet::new();
        s.push(BlsScalar::from(1));
        s.push(BlsScalar::from(2));
        s.push(BlsScalar::from(3));
        s.push(BlsScalar::from(4));
        s.push(BlsScalar::from(5));
        s.push(BlsScalar::from(6));
        s.push(BlsScalar::from(7));

        let domain = EvaluationDomain::new(s.len() + 1).unwrap();
        let s_poly = s.to_polynomial(&domain);

        assert_eq!(s_poly.degree(), 7)
    }
    #[test]
    fn test_is_subset() {
        let mut t = MultiSet::new();
        t.push(BlsScalar::from(1));
        t.push(BlsScalar::from(2));
        t.push(BlsScalar::from(3));
        t.push(BlsScalar::from(4));
        t.push(BlsScalar::from(5));
        t.push(BlsScalar::from(6));
        t.push(BlsScalar::from(7));
        let mut f = MultiSet::new();
        f.push(BlsScalar::from(1));
        f.push(BlsScalar::from(2));
        let mut n = MultiSet::new();
        n.push(BlsScalar::from(8));

        assert!(t.contains_all(&f));
        assert!(!t.contains_all(&n));
    }

    #[test]
    fn test_full_compression_into_s() {
        let mut t = MultiSet::new();

        t.push(BlsScalar::zero());
        t.push(BlsScalar::one());
        t.push(BlsScalar::from(2));
        t.push(BlsScalar::from(3));
        t.push(BlsScalar::from(4));
        t.push(BlsScalar::from(5));
        t.push(BlsScalar::from(6));
        t.push(BlsScalar::from(7));

        let mut f = MultiSet::new();
        f.push(BlsScalar::from(3));
        f.push(BlsScalar::from(6));
        f.push(BlsScalar::from(0));
        f.push(BlsScalar::from(5));
        f.push(BlsScalar::from(4));
        f.push(BlsScalar::from(3));
        f.push(BlsScalar::from(2));
        f.push(BlsScalar::from(0));
        f.push(BlsScalar::from(0));
        f.push(BlsScalar::from(1));
        f.push(BlsScalar::from(2));

        assert!(t.contains_all(&f));

        assert!(t.contains(&BlsScalar::from(2)));

        let s = t.sorted_concat(&f);

        // The sets should be merged but also
        // in the ascending order
        let concatenated_set = MultiSet(vec![
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::from(2),
            BlsScalar::from(2),
            BlsScalar::from(2),
            BlsScalar::from(3),
            BlsScalar::from(3),
            BlsScalar::from(3),
            BlsScalar::from(4),
            BlsScalar::from(4),
            BlsScalar::from(5),
            BlsScalar::from(5),
            BlsScalar::from(6),
            BlsScalar::from(6),
            BlsScalar::from(7),
        ]);

        assert_eq!(s.unwrap(), concatenated_set);
    }

    #[test]
    fn multiset_compression_input() {
        // Alpha is a random challenge from
        // the transcript
        let alpha = BlsScalar::from(2);
        let alpha_squared = alpha * alpha;

        let mut table = WitnessTable3Arity::default();

        // Fill in wires directly, no need to use a
        // plookup table as this will not be going
        // into a proof
        table.from_wire_values(BlsScalar::from(1), BlsScalar::from(2), BlsScalar::from(3));

        // Computed expected result
        let compressed_element =
            MultiSet::compress_three_arity([&table.f_1, &table.f_2, &table.f_3], alpha);

        let actual_element = BlsScalar::from(1)
            + (BlsScalar::from(2) * alpha)
            + (BlsScalar::from(3) * alpha_squared);

        let mut actual_set = MultiSet::new();

        actual_set.push(actual_element);

        assert_eq!(actual_set, compressed_element);
    }
}
