// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! In circuit hashing can be conducted using table lookups from the
//! tables defined in this file

use crate::table::hash_tables::constants::{F, N, S, T_S, V};
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::constraint_system::Variable;
use dusk_plonk::prelude::BlsScalar;
use std::convert::TryInto;

/// A vector x in (F_p)^t goes through r rounds of some round function R.
/// The result is another vector y in (F_p)^t.
#[derive(Debug)]
pub struct HashTable {
    pub first_rows: Vec<[BlsScalar; 4]>,
    pub middle_rows: Vec<[BlsScalar; 4]>,
    pub end_rows: Vec<[BlsScalar; 4]>,
}

impl HashTable {
    /// Create a new hash table.
    pub fn new() -> Self {
        Self {
            first_rows: vec![],
            middle_rows: vec![],
            end_rows: vec![],
        }
    }

    /// The whole lookup table will be constructed in 3 parts: the first rows where the third
    /// entry is derived from the function F, i.e. the rows are of the form (_, _, F(i), ...).
    /// The middle rows are where the first entries are between V+1 and s_i for some i.
    /// The binary rows are at the bottom of the table, and they enumerate all binary possibilities
    /// on T_S bits.
    /// Perhaps the function F can be entered as a vector of its coefficients; I think this would
    /// require knowing the degree of F before hand though in order to be able to evaluate it.
    pub fn f_rows(&mut self) {
        // Have to make sure types of the same, right now V and are usize and BlsScalars.
        // Also need to figure out what this function F is, and how to give it to this
        // table creator
        for i in 0..(V + 1) {
            // println!("i: {}", i);
            let eval: u64 = (F[0] * i as u64) + F[1];
            // println!("eval: {}", eval);
            let perm_eval = BlsScalar::from(eval);
            let row = [
                BlsScalar::from(i as u64),
                BlsScalar::zero(),
                perm_eval,
                -BlsScalar::one(),
            ];

            self.first_rows.push(row);
        }
    }

    /// The middle rows can be created iteratively too by taking in a vector S = (s_1,..., s_n)
    /// in (F_p)^N, and V and N.
    /// Will have to do the same thing as in the first rows to append T_S-3 lots of -1 to the end
    /// of each row.
    pub fn m_rows(&mut self) {
        // Iteratively build each row; the first loop determines which section (V+1 to s_{i+1}),
        // the second determines which row in the section (i.e. (V+j, i+1, ...)), and the third
        // loop iteratively appends all the -1's.
        for i in 0..N {
            let distance = S[i as usize] - V as u64;

            for j in 1..(distance + 1) {
                let mut row = [
                    BlsScalar::from(V as u64 + j),
                    BlsScalar::from(i as u64 + 1),
                    BlsScalar::from(V as u64 + j),
                    -BlsScalar::one(),
                ];

                self.middle_rows.push(row);
            }
        }
    }

    // A function that creates all binary values of word of length T_S,
    // i.e. this is the bottom part of the end hash table we want.
    // It does this in a recursive manner.
    pub fn binary_end_rows(&mut self) {
        // Get all binary combinations
        let combinations = all_outcomes();
        println!("{:?}", combinations);
        combinations.iter().for_each(|c| {
            let mut scalars = [BlsScalar::zero(); T_S];

            for (i, mut v) in scalars.iter().enumerate() {
                v = &BlsScalar::from(c[i] as u64)
            }
            self.end_rows.push(scalars);
        });
    }
}

fn all_outcomes() -> Vec<[u8; T_S]> {
    let mut a = [0u8; T_S];

    let mut results = vec![];

    // Push all-zero result first
    results.push(a.clone());

    for _ in 1..2i32.pow(T_S.try_into().unwrap()) {
        // Carry
        let mut c = 1u8;

        for i in (0..(T_S)).rev() {
            if a[i] == 1 && c == 1 {
                a[i] = 0;
                c = 1;
                continue;
            }

            if a[i] == 0 && c == 1 {
                a[i] = 1;
                c = 0;
            }
        }

        results.push(a.clone());
    }

    results
}

#[cfg(test)]
mod tests {
    use crate::table::hash_tables::tables::HashTable;

    #[test]
    fn test_first() {
        let mut table = HashTable::new();
        table.f_rows();
        println!("The values are: {:?}", table);
    }

    #[test]
    fn test_middle() {
        let mut table = HashTable::new();
        table.m_rows();
        println!("{:?}", table);
    }

    #[test]
    fn test_end() {
        let mut table = HashTable::new();
        table.binary_end_rows();
        println!("{:?}", table);
    }
}
