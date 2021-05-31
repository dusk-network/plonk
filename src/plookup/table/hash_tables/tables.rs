// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fft::Polynomial;
///! In circuit hashing can be conducted using table lookups from the
///! tables defined in this file.
/// This currently assumes that T_S = 4. It is possible that in future T_S > 4,
/// in which case this file will have to be adjusted. T_S is the arity of the
/// vectors.
use crate::plookup::table::hash_tables::constants::{N, T_S, V};
use crate::prelude::BlsScalar;

/// A HashTable consists of three different segments, each of arity
/// vectors containing Bls Scalars. These values are precomputed and
/// stored. These are the retrieved in the lookup functions and placed
/// into seperate structs for the proof.
/// A vector x in (F_p)^t goes through r rounds of a round function R.
/// The result is another vector y in (F_p)^t.
#[derive(Debug)]
pub struct HashTable {
    /// First rows
    pub first_rows: [[BlsScalar; 4]; V + 1],
    /// Middle rows
    pub middle_rows: [[BlsScalar; 4]; 787],
    /// End rows
    pub end_rows: [[BlsScalar; 4]; 16],
}

//     // This function fills in the middle section of the hash table
//     // where the entry is defined as being between V+1 and s_i
//     // for a chosen i. The i here depends on the intialisation
//     // of the first rows.
//     fn m_rows(&mut self) {
//         let mut idx = 0;
//         for i in 0..N {
//             let distance = S[i as usize] - V as u64;

//             for j in 1..(distance + 1) {
//                 let row = [
//                     BlsScalar::from(V as u64 + j),
//                     BlsScalar::from(i as u64 + 1),
//                     BlsScalar::from(V as u64 + j),
//                     -BlsScalar::one(),
//                 ];

//                 self.middle_rows[idx] = row;
//                 idx += 1;
//             }
//         }
//     }

//     // A function that creates all binary values of word of length T_S.
//     // For a width T_S, these are the binary possibilites for numbers
//     // between 0 and 15.
//     fn binary_end_rows(&mut self) {
//         let mut row = [BlsScalar::zero(); 4];
//         self.end_rows[0] = row;

//         for i in 1..(2i32.pow(T_S)) {
//             incrementer(&mut row, 0);
//             self.end_rows[i as usize] = row;
//         }
//     }

//     /// This function constructs a hash table based on the
//     /// constants declared.
//     pub fn construct_table(f: &Polynomial) -> Self {
//         let mut table = HashTable::new();
//         table.f_rows(f);
//         table.m_rows();
//         table.binary_end_rows();

//         table
//     }
// }

// #[cfg(test)]
// mod tests {
//     use crate::fft::Polynomial;
//     use crate::plookup::table::hash_tables::constants::{S, V};
//     use crate::prelude::BlsScalar;
//     // This test allows us to print Table 1, which is hardcoded
//     // but long. So it is archived here to be used when necessary.
//     #[ignore = "Not required unless table needs to be printed"]
//     #[test]
//     fn table_3() {
//         for i in 0..659 {
//             let first = BlsScalar::from(i);
//             let third = BlsScalar::from_raw(SBOX_BLS[i as usize].0);
//             println!(
//                 "[BlsScalar({:?}), 0, BlsScalar({:?}), 1],",
//                 first.0, third.0
//             );
//         }

//         for i in (0..27).rev() {
//             let s_rev_i = DECOMPOSITION_S_I[i].as_u64();
//             let v_rev_i = BLS_SCALAR_REAL[i].as_u64();
//             if i == 26 {
//                 for j in 659..679 {
//                     if j == s_rev_i {
//                         let first = BlsScalar::from(j);
//                         let second = BlsScalar::from((27 - i) as u64);
//                         println!("[BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?})]", first.0, second.0, first.0, BlsScalar::zero().0);
//                     } else {
//                         let first = BlsScalar::from(j);
//                         let second = BlsScalar::from((27 - i) as u64);
//                         println!("[BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?})]", first.0, second.0, first.0, BlsScalar::one().0);
//                     }
//                 }
//             } else {
//                 for j in 659..v_rev_i {
//                     let first = BlsScalar::from(j);
//                     let second = BlsScalar::from((27 - i) as u64);
//                     println!("[BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?})]", first.0, second.0, first.0, BlsScalar::one().0);
//                 }

//                 let first = BlsScalar::from(v_rev_i);
//                 let second = BlsScalar::from((27 - i) as u64);
//                 println!("[BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?})]", first.0, second.0, first.0, BlsScalar::zero().0);
//                 println!("[BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?}), BlsScalar([17179869180, 12756850513266774020, 3681868479150465002, 3479420709561305823])]", first.0, second.0, first.0);

//                 for j in (v_rev_i + 1)..s_rev_i {
//                     let first = BlsScalar::from(j);
//                     let second = BlsScalar::from((27 - i) as u64);
//                     println!("[BlsScalar({:?}), BlsScalar({:?}), BlsScalar({:?}), BlsScalar([17179869180, 12756850513266774020, 3681868479150465002, 3479420709561305823])]", first.0, second.0, first.0);
//                 }
//             }
//         }
//     }
// }

//     #[test]
//     fn test_first() {
//         let mut table = HashTable::new();
//         let f: Polynomial = Polynomial {
//             coeffs: vec![BlsScalar::from(3), BlsScalar::one()],
//         };
//         table.f_rows(&f);
//         // Check that second row of first rows equals [1,0,f(1),-1],
//         // when f(x) = x+3.
//         assert_eq!(
//             table.first_rows[1],
//             [
//                 BlsScalar::one(),
//                 BlsScalar::zero(),
//                 BlsScalar::from(4),
//                 -BlsScalar::one()
//             ]
//         );
//         // Here there is a check that 1 + (-1) = 0, (as BlsScalars).
//         // This is done only for the second row.
//         let expected_zero = table.first_rows[1][0] + table.first_rows[1][3];
//         assert_eq!(expected_zero, BlsScalar::zero());
//     }

//     #[test]
//     fn test_middle() {
//         let mut table = HashTable::new();
//         table.m_rows();
//         let check_first = S[0] as usize - V - 1 as usize;
//         // Check that the first entry of the S[0]-V-1'th row of middle rows is s_1 (i.e. is equal to S[0]).
//         assert_eq!(table.middle_rows[check_first][0], BlsScalar::from(S[0]));
//         let check_last = table.middle_rows.len();
//         // Check that the first entry if the final row is equal to s_27, i.e. equal to S[26].
//         assert_eq!(table.middle_rows[check_last - 1][0], BlsScalar::from(S[26]));
//     }
//     #[test]
//     fn test_end() {
//         let mut table = HashTable::new();
//         table.binary_end_rows();
//         // Check that first binary row is [0,0,0,0].
//         assert_eq!(table.end_rows[0], [BlsScalar::zero(); 4]);
//         // Check that last binary row is [1,1,1,1]. This is assuming T_S = 4.
//         assert_eq!(table.end_rows[15], [BlsScalar::one(); 4]);
//     }

//     #[test]
//     fn test_whole_table() {
//         let f: Polynomial = Polynomial {
//             coeffs: vec![BlsScalar::from(3), BlsScalar::one()],
//         };
//         let table = HashTable::construct_table(&f);

//         // Assert the fixed length of the three parts of the
//         // hash table
//         assert_eq!(644, table.first_rows.len() as usize);
//         assert_eq!(787, table.middle_rows.len() as usize);
//         assert_eq!(16, table.end_rows.len() as usize);
//     }

//     #[test]
//     fn test_incorrect_poly() {
//         // Create polynomial for first table
//         let f_1: Polynomial = Polynomial {
//             coeffs: vec![BlsScalar::from(3), BlsScalar::one()],
//         };
//         // Build complete table
//         let table = HashTable::construct_table(&f_1);

//         // Create polynomial for second table
//         let f_2: Polynomial = Polynomial {
//             coeffs: vec![BlsScalar::from(6), BlsScalar::one()],
//         };

//         // Create table and insert first rows from second poly
//         let mut table_2 = HashTable::new();
//         table_2.f_rows(&f_2);

//         // Assert the tables have different values
//         assert_ne!(table.first_rows, table_2.first_rows);
//     }
// }
