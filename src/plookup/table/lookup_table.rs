// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Structs and functions for LookupTables
//! Denoted as 't' in Plookup paper.

use super::hash_tables::constants::{BLS_SCALAR_REAL, DECOMPOSITION_S_I, SBOX_U256};
use crate::constraint_system::StandardComposer;
use crate::plookup::MultiSet;
use crate::plookup::PlookupErrors;
use crate::prelude::BlsScalar;

/// For the implemenation of look up tables in PLONK, aptly named PLOOKup tables,
/// there will be different fucntions depending on the type of table that needs
/// to be constructed. All tables entries envisioned will be with different arity.
/// Meaning each of the wires will correspond to a column.
///
/// If the standard composer calls a plookup gate, then the user will define
/// the length of the gate, measured in circuit size.

/// This struct is a table, contaning a vector,
/// of arity 3 where each of the values is a
/// BlsScalar. The elements of the table are
/// determined by the function g for
/// g(x,y), used to compute tuples.
///
/// This struct will be used to determine
/// the outputs of gates within arithmetic
/// circuits.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PlookupTable3Arity(Vec<[BlsScalar; 3]>);

impl PlookupTable3Arity {
    /// Constructs a Lookup table of four columns corresponding to
    /// vectors of witness values, a,b c, and d. The function
    /// takes in a chosen number of 2^n values for the first column,
    /// containing values of a. Then builds the combinations with b
    /// and results them, modular the n, to construct c.
    ///
    /// The domain of the table is defined by the user. By default, it
    /// will be 0 -> domain input. However, for checks within certain
    /// ranges, the user will be able to specify values to and from.
    /// The inputted domain size will apply only to the first column
    /// and the corresponding columns will be filled in and an assertion
    /// that they are equal in length will be given.
    ///
    /// XXX: Decide what use cases the 4th wire requires
    ///
    /// Function takes in two different usize numbers and checks the range
    /// between them, as well as computing the value of their additions.
    /// These numbers require exponentiation outside, for the lower bound,
    /// otherwise the range cannot start from zero, as 2^0 = 1.
    pub fn add_table(lower_bound: u64, n: u8) -> Self {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        let cap = ((upper_bound - lower_bound) * upper_bound) as usize;

        let mut table: Vec<[BlsScalar; 3]> = Vec::with_capacity(cap);

        for a in range.clone() {
            range
                .clone()
                .map(|b| {
                    let c = (a + b) % upper_bound;
                    [BlsScalar::from(a), BlsScalar::from(b), BlsScalar::from(c)]
                })
                .for_each(|row| {
                    table.push(row);
                });
        }

        PlookupTable3Arity(table)
    }

    /// Function takes in two different usize numbers and checks the range
    /// between them, as well as computing the value of their XOR operation.
    /// These numbers require exponentiation outside, for the lower bound,
    /// otherwise the range cannot start from zero, as 2^0 = 1.
    pub fn xor_table(lower_bound: u64, n: u8) -> Self {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        let cap = ((upper_bound - lower_bound) * upper_bound) as usize;

        let mut table: Vec<[BlsScalar; 3]> = Vec::with_capacity(cap);

        for a in range.clone() {
            range
                .clone()
                .map(|b| {
                    let c = (a ^ b) % upper_bound;
                    [BlsScalar::from(a), BlsScalar::from(b), BlsScalar::from(c)]
                })
                .for_each(|row| {
                    table.push(row);
                });
        }

        PlookupTable3Arity(table)
    }

    /// Function takes in two different usize numbers and checks the range
    /// between them, as well as computing the value of their product.
    /// These numbers require exponentiation outside, for the lower bound,
    /// otherwise the range cannot start from zero, as 2^0 = 1.
    pub fn mul_table(lower_bound: u64, n: u8) -> Self {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        let cap = ((upper_bound - lower_bound) * upper_bound) as usize;

        let mut table: Vec<[BlsScalar; 3]> = Vec::with_capacity(cap);

        for a in range.clone() {
            range
                .clone()
                .map(|b| {
                    let c = (a * b) % upper_bound;
                    [BlsScalar::from(a), BlsScalar::from(b), BlsScalar::from(c)]
                })
                .for_each(|row| {
                    table.push(row);
                });
        }

        PlookupTable3Arity(table)
    }

    // Function takes in two different usize numbers and checks the range
    /// between them, as well as computing the value of their AND bitwise
    /// operation. These numbers require exponentiation outside, for the lower
    /// bound, otherwise the range cannot start from zero, as 2^0 = 1.
    pub fn and_table(lower_bound: u64, n: u8) -> Self {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        let cap = ((upper_bound - lower_bound) * upper_bound) as usize;

        let mut table: Vec<[BlsScalar; 3]> = Vec::with_capacity(cap);

        for a in range.clone() {
            range
                .clone()
                .map(|b| {
                    let c = (a & b) % upper_bound;
                    [BlsScalar::from(a), BlsScalar::from(b), BlsScalar::from(c)]
                })
                .for_each(|row| {
                    table.push(row);
                });
        }

        PlookupTable3Arity(table)
    }

    /// Function that generates the S-box used in reinforced concrete
    pub fn s_box_table() -> Self {
        let mut s_box = Vec::with_capacity(659);
        (0..659).for_each(|k| {
            s_box.push([
                BlsScalar([k, 0, 0, 0]),
                BlsScalar([k, 0, 0, 0]),
                BlsScalar(SBOX_U256[k as usize].0),
            ]);
        });

        PlookupTable3Arity(s_box)
    }

    /// Takes in a table, which is a list of vectors containing
    /// 3 elements, and turns them into 3 distinct multisets for
    /// a, b and c.
    pub fn vec_to_multiset(&self) -> (MultiSet, MultiSet, MultiSet) {
        let mut multiset_a = MultiSet::new();
        let mut multiset_b = MultiSet::new();
        let mut multiset_c = MultiSet::new();

        self.0.iter().for_each(|row| {
            multiset_a.push(row[0]);
            multiset_b.push(row[1]);
            multiset_c.push(row[2]);
        });

        (multiset_a, multiset_b, multiset_c)
    }

    /// Attempts to find an output value, given two input values, by querying the lookup
    /// table. If the element does not exist, it will return an error.
    pub fn lookup(&self, a: BlsScalar, b: BlsScalar) -> Result<BlsScalar, PlookupErrors> {
        let pos = self
            .0
            .iter()
            .position(|row| row[0] == a && row[1] == b)
            .ok_or(PlookupErrors::ElementNotIndexed)?;

        Ok(self.0[pos][2])
    }
}

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
pub struct PlookupTable4Arity(pub Vec<[BlsScalar; 4]>);

impl Default for PlookupTable4Arity {
    fn default() -> Self {
        PlookupTable4Arity::new()
    }
}

impl PlookupTable4Arity {
    /// Create a new, empty Plookup table, with arity 4.
    pub fn new() -> Self {
        PlookupTable4Arity(vec![])
    }

    /// Insert a new row for an addition operation.
    /// This function needs to know the upper bound of the amount of addition
    /// operations that will be done in the plookup table.
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
    /// operations that will be done in the plookup table.
    pub fn insert_special_row(&mut self, a: BlsScalar, b: BlsScalar, c: BlsScalar, d: BlsScalar) {
        self.0.push([a, b, c, d]);
    }

    /// Insert a new row for an multiplication operation.
    /// This function needs to know the upper bound of the amount of multiplication
    /// operations that will be done in the plookup table.
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
    /// operations that will be done in the plookup table.
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
    /// operations that will be done in the plookup table.
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

    /// Attempts to find an output value, given two input values, by querying the lookup
    /// table. The final wire holds the index of the table. The element must be predetermined
    /// to be between -1 and 2 depending on the type of table used.
    /// If the element does not exist, it will return an error.
    pub fn lookup(
        &self,
        a: BlsScalar,
        b: BlsScalar,
        d: BlsScalar,
    ) -> Result<BlsScalar, PlookupErrors> {
        let pos = self
            .0
            .iter()
            .position(|row| row[0] == a && row[1] == b && row[3] == d)
            .ok_or(PlookupErrors::ElementNotIndexed)?;

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
            table.push([BlsScalar::zero(), BlsScalar::one(), two, BlsScalar::from(i)])
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
            let third = BlsScalar::from_raw(SBOX_U256[k as usize].0);
            table.push([first, BlsScalar::zero(), third, BlsScalar::one()]);
        }
        // Build the remaining 27 sections that range from p' to s_i (except
        // when i=1)
        for k in (0..27).rev() {
            // The rev denotes that it is inverted, so s_rev_26 will actually be s_1
            // (i.e. i = 27-k)
            let s_rev_k = DECOMPOSITION_S_I[k].0[0];
            let v_rev_k = BLS_SCALAR_REAL[k].as_u64();
            // If i=1, then we go to v_1 and not s_1
            if k == 26 {
                // v_1 = 678
                for j in 659..(v_rev_k + 1) {
                    // Fourth column is 1, unless j=v_i, in which case it is 0
                    if j == v_rev_k {
                        let first = BlsScalar::from(j);
                        table.push([first, BlsScalar::one(), first, BlsScalar::zero()]);
                    } else {
                        let first = BlsScalar::from(j);
                        table.push([first, BlsScalar::one(), first, BlsScalar::one()]);
                    }
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

        PlookupTable4Arity(table)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add_table() {
        let n = 4;

        let table = PlookupTable3Arity::add_table(0, n);

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

        let table = PlookupTable3Arity::xor_table(0, n);

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

        let table = PlookupTable3Arity::mul_table(0, n);

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
    fn test_lookup_arity_3() {
        let add_table = PlookupTable3Arity::add_table(0, 3);

        assert!(add_table
            .lookup(BlsScalar::from(2), BlsScalar::from(3))
            .is_ok());

        let output = add_table.0[1][0] + add_table.0[1][1];

        assert_eq!(output, BlsScalar::one());

        let second_output = add_table.0[12][0] + add_table.0[12][1];

        assert_eq!(second_output, BlsScalar::from(5));
    }

    #[test]
    fn test_missing_lookup_value() {
        let xor_table = PlookupTable3Arity::xor_table(0, 5);

        assert!(xor_table
            .lookup(BlsScalar::from(17), BlsScalar::from(367))
            .is_err());
    }

    #[test]
    fn test_concatenated_table() {
        let mut table = PlookupTable4Arity::new();

        table.insert_multi_xor(0, 5);
        table.insert_multi_add(4, 7);

        assert_eq!(table.0.last().unwrap()[2], BlsScalar::from(126u64));
        let xor = table.0[36][0] ^ table.0[36][1];
        assert_eq!(xor, BlsScalar::from(5u64));
    }
}
