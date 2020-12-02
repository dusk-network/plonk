// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::constraint_system::Variable;
use dusk_plonk::prelude::BlsScalar;

/// For the implemenation of look up tables in PLONK, aptly named PLOOKup tables,
/// there will be different fucntions depending on the type of table that needs
/// to be constructed. All tables entries envisioned will be with arity 4. Meaning
/// each of the wires will correspond to a column.
///
/// If the standard composer calls a plookup gate, then the user will define
/// the length of the gate, which is measured in terms of
#[derive(Debug)]
pub struct PlookupTable3Arity(pub Vec<[BlsScalar; 3]>);

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
}
/// This is a table, either
pub struct PlookupTable4Arity(pub Vec<[BlsScalar; 4]>);

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

    pub fn insert_multi_mul(&mut self, lower_bound: u64, n: u8) {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        for a in range.clone() {
            range
                .clone()
                .for_each(|b| self.insert_mul_row(a, b, upper_bound));
        }
    }

    pub fn insert_multi_xor(&mut self, lower_bound: u64, n: u8) {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        for a in range.clone() {
            range
                .clone()
                .for_each(|b| self.insert_xor_row(a, b, upper_bound));
        }
    }
}

pub struct PrecomputedT();

/*
pub fn get_challenge(&Self) -> BlsScalar {
unimplemented!()
    }
*/

#[cfg(test)]
mod test {
    use super::*;
    use dusk_plonk::constraint_system::StandardComposer;

    #[test]
    fn test_add_table() {
        let n = 4;

        let table = PlookupTable3Arity::add_table(0, n);

        // println!("{:?}", table);

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
}
