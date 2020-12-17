// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! In circuit hashing can be conducted using table lookups from the
//! tables defined in this file

use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::constraint_system::Variable;
use dusk_plonk::prelude::BlsScalar;
use crate::table::hash_tables::constants::{V, N, S, T_S, F};

/// A vector x in (F_p)^t goes through r rounds of some round function R.
/// The result is another vector y in (F_p)^t.
#[derive(Debug)]
pub struct HashTable(pub Vec<[BlsScalar; 4]>);

impl HashTable {
    /// Create a new hash table.
    pub fn new() -> Self {
        Self(vec![])
    }

    /// The whole lookup table will be constructed in 3 parts: the first rows where the third
    /// entry is derived from the function F, i.e. the rows are of the form (_, _, F(i), ...).
    /// The middle rows are where the first entries are between V+1 and s_i for some i.
    /// The binary rows are at the bottom of the table, and they enumerate all binary possibilities
    /// on T_S bits.
    /// Perhaps the function F can be entered as a vector of its coefficients; I think this would
    /// require knowing the degree of F before hand though in order to be able to evaluate it.
    pub fn first_rows(&mut self) {
        // Have to make sure types of the same, right now V and are usize and BlsScalars.
        // Also need to figure out what this function F is, and how to give it to this
        // table creator
        for i in 0..(V+1) {
            // println!("i: {}", i);
            let eval: u64 = (F[0] * i as u64) + F[1];
            // println!("eval: {}", eval);
            let perm_eval = BlsScalar::from(eval);
            let row = [BlsScalar::from(i as u64), BlsScalar::zero(), perm_eval, -BlsScalar::one()];

            // Need to push T_S-3 lots of -1 to the end of each vector
            // for j in 0..(T_S - 3) {
            //     row.push(-BlsScalar::one());
            // }

            self.0.push(row);
        }
        // println!("f_rows: {:?}", f_rows);
    }

    /// The middle rows can be created iteratively too by taking in a vector S = (s_1,..., s_n)
    /// in (F_p)^N, and V and N.
    /// Will have to do the same thing as in the first rows to append T_S-3 lots of -1 to the end
    /// of each row.
    pub fn middle_rows(&mut self) {
        // Iteratively build each row; the first loop determines which section (V+1 to s_{i+1}),
        // the second determines which row in the section (i.e. (V+j, i+1, ...)), and the third
        // loop iteratively appends all the -1's.
        for i in 0..N {
            let distance = S[i as usize] - V as u64;

            for j in 1..(distance + 1) {
                let mut row = [BlsScalar::from(V as u64 + j), BlsScalar::from(i as u64 + 1), BlsScalar::from(V as u64 + j), -BlsScalar::one()];

                // for k in 0..(T_S - 3) {
                //     row.push(-BlsScalar::one());
                // }

                self.0.push(row);
            }
        }     
    }
}

//     // A function that creates all binary values of word of length T_S,
//     // i.e. this is the bottom part of the end hash table we want.
//     // It does this in a recursive manner.
//     pub fn binary_rows(T_S: u64) -> Self {
//         let mut table: Vec<[BlsScalar; T_S]> = Vec.with_capacity(2i32.pow(T_S.try_into().unwrap()));
//         let mut row = [BlsScalar::zero()];

//         for i in 1..T_S {
//             row.push(BlsScalar::zero());
//         }

//         table.push(row);

//         for i in 1..(2i32.pow(T_S)) {
//             let mut j = 0;
//             row = iterator(&mut row, &mut j, T_S);
//             table.push(row);
//         }

//         HashTable(table)
//     }
// }

// pub fn iterator(&mut row: [BlsScalar; 4], &mut j: usize, T_S) -> [BlsScalar; T_S] {
//     let pos = (T_S - 1) - j;
//     if row[pos] == BlsScalar::zero() {
//         row[pos] = BlsScalar::one();
//     } else {
//         row[pos] = BlsScalar::one();
//         iterator(&mut row, mut j, T_S);
//     }

//     HashTable(row)
// }



#[cfg(test)]
mod tests {
    use crate::table::hash_tables::tables::HashTable;

    #[test]
    fn test_first() {
        let mut table = HashTable::new();
        table.first_rows();
        println!("The values are: {:?}", table);
    }
}