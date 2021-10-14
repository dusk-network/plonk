// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Structs and functions for LookupTables
//! Denoted as 't' in Plonkup paper.

use super::hash_tables::constants::{BLS_SCALAR_REAL, DECOMPOSITION_S_I, SBOX};
use crate::error::Error;
use crate::plonkup::MultiSet;
use crate::prelude::BlsScalar;
use alloc::vec::Vec;

/// This struct is a table, contaning a vector,
/// of arity 4 where each of the values is a
/// BlsScalar. The elements of the table are
/// determined by the function g for
/// g(x,y), used to compute tuples.
///
/// This struct will be used to determine
/// the outputs of gates within arithmetic
/// circuits.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct IndexTable(pub Vec<[BlsScalar; 4]>);

impl Default for IndexTable {
    fn default() -> Self {
        IndexTable::new()
    }
}

impl IndexTable {
    /// Create a new, empty Plonkup table, with arity 4.
    pub fn new() -> Self {
        IndexTable(vec![])
    }

    /// Insert a new row for an addition operation.
    /// This function needs to know the upper bound of the amount of addition
    /// operations that will be done in the plonkup table.
    pub fn insert_add_row(&mut self, a: u64, b: u64, upper_bound: u64) {
        let c = (a + b) % upper_bound;
        self.0.push([
            BlsScalar::from(a),
            BlsScalar::from(b),
            BlsScalar::from(c),
            BlsScalar::zero(),
        ]);
    }

    /// Insert a new row for an addition operation.
    /// This function needs to know the upper bound of the amount of addition
    /// operations that will be done in the plonkup table.
    pub fn insert_special_row(
        &mut self,
        a: BlsScalar,
        b: BlsScalar,
        c: BlsScalar,
        d: BlsScalar,
    ) {
        self.0.push([a, b, c, d]);
    }

    /// Insert a new row for an multiplication operation.
    /// This function needs to know the upper bound of the amount of
    /// multiplication operations that will be done in the plonkup table.
    pub fn insert_mul_row(&mut self, a: u64, b: u64, upper_bound: u64) {
        let c = (a * b) % upper_bound;
        self.0.push([
            BlsScalar::from(a),
            BlsScalar::from(b),
            BlsScalar::from(c),
            BlsScalar::one(),
        ]);
    }

    /// Insert a new row for an XOR operation.
    /// This function needs to know the upper bound of the amount of XOR
    /// operations that will be done in the plonkup table.
    pub fn insert_xor_row(&mut self, a: u64, b: u64, upper_bound: u64) {
        let c = (a ^ b) % upper_bound;
        self.0.push([
            BlsScalar::from(a),
            BlsScalar::from(b),
            BlsScalar::from(c),
            -BlsScalar::one(),
        ]);
    }

    /// Insert a new row for an AND operation.
    /// This function needs to know the upper bound of the amount of XOR
    /// operations that will be done in the plonkup table.
    pub fn insert_and_row(&mut self, a: u64, b: u64, upper_bound: u64) {
        let c = (a & b) % upper_bound;
        self.0.push([
            BlsScalar::from(a),
            BlsScalar::from(b),
            BlsScalar::from(c),
            BlsScalar::from(2u64),
        ]);
    }

    /// Function builds a table from more than one operation. This is denoted
    /// as 'Multiple Tables' in the paper. If, for example, we are using lookup
    /// tables for both XOR and mul operataions, we can create a table where the
    /// rows 0..n/2 use a mul function on all 2^n indices and have the 4th wire
    /// storing index 0. For all indices n/2..n, an XOR gate can be added, where
    /// the index of the 4th wire is 0.
    /// These numbers require exponentiation outside, for the lower bound,
    /// otherwise the range cannot start from zero, as 2^0 = 1.
    pub fn insert_multi_add(&mut self, lower_bound: u64, n: u8) {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        for a in range.clone() {
            range
                .clone()
                .for_each(|b| self.insert_add_row(a, b, upper_bound));
        }
    }

    /// Function builds a table from mutiple operations. If, for example,
    /// we are using lookup tables for both XOR and mul operataions, we can
    /// create a table where the rows 0..n/2 use a mul function on all 2^n
    /// indices and have the 4th wire storing index 0. For all indices n/2..n,
    /// an XOR gate can be added, wheren the index of the 4th wire is 0.
    /// These numbers require exponentiation outside, for the lower bound,
    /// otherwise the range cannot start from zero, as 2^0 = 1.
    /// Particular multiplication row(s) can be added with this function.
    pub fn insert_multi_mul(&mut self, lower_bound: u64, n: u8) {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        for a in range.clone() {
            range
                .clone()
                .for_each(|b| self.insert_mul_row(a, b, upper_bound));
        }
    }

    /// Function builds a table from mutiple operations. If, for example,
    /// we are using lookup tables for both XOR and mul operataions, we can
    /// create a table where the rows 0..n/2 use a mul function on all 2^n
    /// indices and have the 4th wire storing index 0. For all indices n/2..n,
    /// an XOR gate can be added, wheren the index of the 4th wire is 0.
    /// These numbers require exponentiation outside, for the lower bound,
    /// otherwise the range cannot start from zero, as 2^0 = 1.
    /// Particular XOR row(s) can be added with this function.
    pub fn insert_multi_xor(&mut self, lower_bound: u64, n: u8) {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        for a in range.clone() {
            range
                .clone()
                .for_each(|b| self.insert_xor_row(a, b, upper_bound));
        }
    }

    /// Function builds a table from mutiple operations. If, for example,
    /// we are using lookup tables for both XOR and mul operataions, we can
    /// create a table where the rows 0..n/2 use a mul function on all 2^n
    /// indices and have the 4th wire storing index 0. For all indices n/2..n,
    /// an XOR gate can be added, wheren the index of the 4th wire is 0.
    /// These numbers require exponentiation outside, for the lower bound,
    /// otherwise the range cannot start from zero, as 2^0 = 1.
    /// Particular AND row(s) can be added with this function.
    pub fn insert_multi_and(&mut self, lower_bound: u64, n: u8) {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        for a in range.clone() {
            range
                .clone()
                .for_each(|b| self.insert_and_row(a, b, upper_bound));
        }
    }

    /// Takes in a table, which is a list of vectors containing
    /// 4 elements, and turns them into 4 distinct multisets for
    /// a, b, c and d.
    pub fn vec_to_multiset(&self) -> (MultiSet, MultiSet, MultiSet, MultiSet) {
        let mut multiset_a = MultiSet::new();
        let mut multiset_b = MultiSet::new();
        let mut multiset_c = MultiSet::new();
        let mut multiset_d = MultiSet::new();

        self.0.iter().for_each(|row| {
            multiset_a.push(row[0]);
            multiset_b.push(row[1]);
            multiset_c.push(row[2]);
            multiset_d.push(row[3]);
        });

        (multiset_a, multiset_b, multiset_c, multiset_d)
    }

    /// Attempts to find an output value, given two input values, by querying
    /// the lookup table. The final wire holds the index of the table. The
    /// element must be predetermined to be between -1 and 2 depending on
    /// the type of table used. If the element does not exist, it will
    /// return an error.
    pub fn lookup(
        &self,
        a: BlsScalar,
        b: BlsScalar,
        d: BlsScalar,
    ) -> Result<BlsScalar, Error> {
        let pos = self
            .0
            .iter()
            .position(|row| row[0] == a && row[1] == b && row[3] == d)
            .ok_or(Error::ElementNotIndexed)?;

        Ok(self.0[pos][2])
    }

    /// Function that creates the table needed for reinforced concrete.
    /// Creates one table that is the concatenation T_2 || T_3 || T_1
    /// from the paper
    pub fn create_hash_table() -> Self {
        let mut table = Vec::new();
        let two = BlsScalar::from(2);

        // Build the T_2 part
        // (0..2).for_each(|i| {
        //     (0..2).for_each(|j| {
        //         (0..2).for_each(|k| {
        //             (0..2).for_each(|m| {
        //                 table.push([
        //                     BlsScalar::from(i),
        //                     BlsScalar::from(j),
        //                     BlsScalar::from(k),
        //                     BlsScalar::from(m),
        //                 ])
        //             })
        //         })
        //     })
        // });

        // Add the parts of T_2 that aren't in T_3
        (0..2).for_each(|i| {
            (0..2).for_each(|j| {
                (0..2).for_each(|k| {
                    if (i, j, k) != (1, 1, 1) {
                        table.push([
                            BlsScalar::one(),
                            BlsScalar::from(i),
                            BlsScalar::from(j),
                            BlsScalar::from(k),
                        ])
                    }
                })
            })
        });
        (0..2).for_each(|i| {
            (0..2).for_each(|j| {
                if (i, j) != (1, 1) {
                    table.push([
                        BlsScalar::zero(),
                        BlsScalar::one(),
                        BlsScalar::from(i),
                        BlsScalar::from(j),
                    ])
                }
            })
        });
        table.push([
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::one(),
            BlsScalar::zero(),
        ]);

        // Build the T_3 part
        (0..2).for_each(|i| {
            table.push([
                BlsScalar::zero(),
                BlsScalar::zero(),
                BlsScalar::zero(),
                BlsScalar::from(i),
            ])
        });
        (0..2).for_each(|i| {
            (1..3).for_each(|j| {
                table.push([
                    BlsScalar::zero(),
                    BlsScalar::from(i),
                    BlsScalar::one(),
                    BlsScalar::from(j),
                ])
            })
        });
        (1..3).for_each(|i| {
            table.push([
                BlsScalar::zero(),
                BlsScalar::one(),
                two,
                BlsScalar::from(i),
            ])
        });
        (1..3).for_each(|i| {
            (1..3).for_each(|j| {
                (1..3).for_each(|k| {
                    (1..3).for_each(|m| {
                        table.push([
                            BlsScalar::from(i),
                            BlsScalar::from(j),
                            BlsScalar::from(k),
                            BlsScalar::from(m),
                        ])
                    })
                })
            })
        });

        // Construct the T_1 part
        // Build the permutation part of the table (the top section)
        for k in 0..659 {
            let first = BlsScalar::from(k);
            let third = BlsScalar::from_raw([SBOX[k as usize] as u64, 0, 0, 0]);
            table.push([first, BlsScalar::zero(), third, BlsScalar::one()]);
        }
        // Build the remaining 27 sections that range from p' to s_i (except
        // when i=1)
        for k in (0..27).rev() {
            // The rev denotes that it is inverted, so s_rev_26 will actually be
            // s_1 (i.e. i = 27-k)
            let s_rev_k = DECOMPOSITION_S_I[k].0[0];
            let v_rev_k = BLS_SCALAR_REAL[k] as u64;
            // If i=1, then we go to v_1 and not s_1
            if k == 26 {
                // v_1 = 678
                for j in 659..(v_rev_k + 1) {
                    let first = BlsScalar::from(j as u64);

                    // Fourth column is 1, unless j=v_i, in which case it is 0
                    let fourth = if j == v_rev_k {
                        BlsScalar::zero()
                    } else {
                        BlsScalar::one()
                    };

                    table.push([first, BlsScalar::one(), first, fourth]);
                }
            } else {
                // When j is between p' and v_i the fourth column is always 1
                let second = BlsScalar::from((27 - k) as u64);
                for j in 659..v_rev_k {
                    let first = BlsScalar::from(j);
                    table.push([first, second, first, BlsScalar::one()]);
                }

                // When we get to j=v_i the fourth column can be either 0 or 2
                let first = BlsScalar::from(v_rev_k);
                table.push([first, second, first, BlsScalar::zero()]);
                table.push([first, second, first, two]);

                // For j between v_i and s_i the fourth column is always 2
                for j in (v_rev_k + 1)..s_rev_k {
                    let first = BlsScalar::from(j);
                    table.push([first, second, first, two]);
                }
            }
        }

        IndexTable(table)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add_table() {
        let n = 4;

        let table = {
            let mut table = IndexTable::default();
            table.insert_multi_add(0, n);
            table
        };

        // Create an identical matrix, but with std numbers.
        // This way, we can also do the modulo operation, and properly
        // check all results.
        let mut i = 0;
        let p = 2u64.pow(n as u32);
        (0..p).for_each(|a| {
            (0..p).for_each(|b| {
                let c = (a + b) % p;
                assert_eq!(BlsScalar::from(c), table.0[i][2]);
                i += 1;
            })
        });

        assert_eq!(
            table.0.len() as u64,
            2u64.pow(n as u32) * 2u64.pow(n as u32)
        );
    }

    #[test]
    fn test_xor_table() {
        let n = 4;

        let table = {
            let mut table = IndexTable::default();
            table.insert_multi_xor(0, n);
            table
        };

        // println!("{:?}", table);
        let mut i = 0;
        let p = 2u64.pow(n as u32);
        (0..p).for_each(|a| {
            (0..p).for_each(|b| {
                let c = (a ^ b) % p;
                assert_eq!(BlsScalar::from(c), table.0[i][2]);
                i += 1;
            })
        });

        assert_eq!(
            table.0.len() as u64,
            2u64.pow(n as u32) * 2u64.pow(n as u32)
        );
    }

    #[test]
    fn test_mul_table() {
        let n = 4;

        let table = {
            let mut table = IndexTable::default();
            table.insert_multi_mul(0, n);
            table
        };

        // println!("{:?}", table);
        let mut i = 0;
        let p = 2u64.pow(n as u32);
        (0..p).for_each(|a| {
            (0..p).for_each(|b| {
                let c = (a * b) % p;
                assert_eq!(BlsScalar::from(c), table.0[i][2]);
                i += 1;
            })
        });

        assert_eq!(
            table.0.len() as u64,
            2u64.pow(n as u32) * 2u64.pow(n as u32)
        );
    }

    #[test]
    fn test_lookup() {
        let add_table = {
            let mut table = IndexTable::default();
            table.insert_multi_add(0, 3);
            table
        };

        assert!(add_table
            .lookup(BlsScalar::from(2), BlsScalar::from(3), BlsScalar::zero())
            .is_ok());

        let output = add_table.0[1][0] + add_table.0[1][1] + add_table.0[1][2]; // TODO are we sure this is right

        assert_eq!(output, BlsScalar::from(2));

        let second_output =
            add_table.0[12][0] + add_table.0[12][1] + add_table.0[12][2]; // TODO are we sure this is right

        assert_eq!(second_output, BlsScalar::from(10));
    }

    #[test]
    fn test_missing_lookup_value() {
        let xor_table = {
            let mut table = IndexTable::default();
            table.insert_multi_xor(0, 5);
            table
        };

        assert!(xor_table
            .lookup(
                BlsScalar::from(17),
                BlsScalar::from(367),
                BlsScalar::from(1)
            )
            .is_err());
    }

    #[test]
    fn test_concatenated_table() {
        let mut table = IndexTable::new();

        table.insert_multi_xor(0, 5);
        table.insert_multi_add(4, 7);

        assert_eq!(table.0.last().unwrap()[2], BlsScalar::from(126u64));
        let xor = table.0[36][0] ^ table.0[36][1] ^ table.0[36][2];
        assert_eq!(xor, BlsScalar::zero());
    }
}
