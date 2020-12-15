// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::bls12_381::BlsScalar;
use dusk_plonk::fft::{EvaluationDomain, Polynomial};
use std::ops::{Add, Mul};
/// MultiSet is struct containing vectors of scalars, which
/// individually represents either a wire value or an index
/// of a PlookUp table
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MultiSet(pub Vec<BlsScalar>);

impl MultiSet {
    // Creates an empty vector with a multiset wrapper around it
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

    /// Fetches last element in MultiSet
    pub fn last(&self) -> BlsScalar {
        *self.0.last().unwrap()
    }
    fn from_slice(slice: &[BlsScalar]) -> MultiSet {
        MultiSet(slice.to_vec())
    }
    /// Returns the cardinality of the multiset
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Returns the position of the element in the Multiset
    /// Panics if element is not in the Multiset
    pub fn pos(&self, element: &BlsScalar) -> usize {
        let index = self.0.iter().position(|&x| x == *element).unwrap();
        index
    }

    /// Concatenates and sorts two Multisets together.
    /// From the Plookup paper, if we have t: {1,2,4,3}
    /// and f: {2,3,4,1}.
    /// We first check if all elements of f exist in t
    /// Then we combine the multisets together and sort
    /// their elements together. The final MultiSet will
    /// look as follows, s: {1,1,2,2,3,3,4,4}
    pub fn sort_and_index(&self, f: &MultiSet) -> MultiSet {
        let mut s: Vec<BlsScalar> = Vec::with_capacity(self.0.len() + f.0.len());
        let mut s = f.clone();
        for element in self.0.iter() {
            let index = s.pos(element);
            s.0.insert(index, *element);
        }

        s
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
    pub fn compress_three_arity(multisets: Vec<&MultiSet>, alpha: BlsScalar) -> MultiSet {
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
    pub fn compress_four_arity(multisets: Vec<&MultiSet>, alpha: BlsScalar) -> MultiSet {
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
