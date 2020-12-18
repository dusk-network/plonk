// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! In circuit hashing can be conducted using table lookups from the
//! tables defined in this file
// This currently assumes that T_S = 4. It is possible that in future T_S > 4,
// in which case this file will ahve to be adjusted.

use crate::table::hash_tables::constants::{F, N, S, T_S, V};
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::constraint_system::Variable;
use dusk_plonk::prelude::BlsScalar;
use std::convert::TryInto;

/// A vector x in (F_p)^t goes through r rounds of a round function R.
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
    pub fn f_rows(&mut self) {
        for i in 0..(V + 1) {
            let eval: u64 = (F[0] * i as u64) + F[1];
            let row = [
                BlsScalar::from(i as u64),
                BlsScalar::zero(),
                BlsScalar::from(eval),
                -BlsScalar::one(),
            ];

            self.first_rows.push(row);
        }
    }

    pub fn m_rows(&mut self) {
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
    pub fn binary_end_rows(&mut self) {
        let mut row = [BlsScalar::zero(); 4];
        self.end_rows.push(row);

        for i in 1..(2i32.pow(T_S.try_into().unwrap())) {
            incrementer(&mut row, 0);
            self.end_rows.push(row);
        }
    }

}

pub fn incrementer(mut row: &mut [BlsScalar; 4], i: usize) {
    if row[3-i] == BlsScalar::zero() {
        row[3-i] = BlsScalar::one();
    } else {
        row[3-i] = BlsScalar::zero();
        incrementer(&mut row, i+1);
    }
}


#[cfg(test)]
mod tests {
    use crate::table::hash_tables::tables::HashTable;
    use dusk_plonk::prelude::BlsScalar;
    use crate::table::hash_tables::constants::{F, N, S, T_S, V};

    #[test]
    fn test_first() {
        let mut table = HashTable::new();
        table.f_rows();
        // Check that second row of first rows equals [1,0,f(1),-1] when f(x)=x+3.
        assert_eq!(table.first_rows[1], 
            [BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::from(4),
            -BlsScalar::one()
            ]);
        // Here I am trying to check that 1 + (-1) = 0, (as BlsScalars).
        // This is done only for the second row though.
        let hopefully_zero = table.first_rows[1][0] + table.first_rows[1][3];
        assert_eq!(hopefully_zero, BlsScalar::zero());
    }

    #[test]
    fn test_middle() {
        let mut table = HashTable::new();
        table.m_rows();
        let check1 = S[0] as usize - V - 1 as usize;
        // Check that the first entry of the S[0]-V-1'th row of middle rows is s_1 (i.e. is equal to S[0]).
        assert_eq!(table.middle_rows[check1][0], BlsScalar::from(S[0]));
        let check_end = table.middle_rows.len();
        // Check that the first entry if the final row is equal to s_27, i.e. equal to S[26].
        assert_eq!(table.middle_rows[check_end-1][0], BlsScalar::from(S[26]));
    }

    #[test]
    fn test_end() {
        let mut table = HashTable::new();
        table.binary_end_rows();         
        // Check that first binary row is [0,0,0,0].
        assert_eq!(table.end_rows[0], [BlsScalar::zero(); 4]);
        // Check that last binary row is [1,1,1,1]. This is assuming T_S = 4.
        assert_eq!(table.end_rows[15], [BlsScalar::one(); 4]);
    }


}
