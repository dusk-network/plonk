// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use crate::prelude::BlsScalar;

/// For the implemenation of look up tables in PLONK, aptly named PLOOKup tables,
/// there will be different fucntions depending on the type of table that needs
/// to be constructed. All tables entries envisioned will be with arity 4. Meaning
/// each of the wires will correspond to a column.
///
/// If the standard composer calls a plookup gate, then the user will define
/// the length of the gate, which is measured in terms of
#[derive(Debug)]
pub struct PlookupTable(pub Vec<[BlsScalar; 4]>);

impl PlookupTable {
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
    /// These numbers require exponentiation outside, otherwise the range cannot
    /// start from zero, as 2^0 = 1.
    pub fn add_table(lower_bound: u64, n: u8) -> Self {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        let cap = ((upper_bound - lower_bound) * upper_bound) as usize;

        let mut table: Vec<[BlsScalar; 4]> = Vec::with_capacity(cap);

        for a in range.clone() {
            range
                .clone()
                .map(|b| {
                    let c = (a + b) % upper_bound;
                    [
                        BlsScalar::from(a),
                        BlsScalar::from(b),
                        BlsScalar::from(c),
                        BlsScalar::zero(),
                    ]
                })
                .for_each(|row| {
                    table.push(row);
                });
        }

        PlookupTable(table)
    }

    /// Function takes in two different usize numbers and checks the range
    /// between them, as well as computing the value of their XOR operation.
    /// These numbers require exponentiation outside, otherwise the range cannot
    /// start from zero, as 2^0 = 1.
    pub fn xor_table(lower_bound: u64, n: u8) -> Self {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        let cap = ((upper_bound - lower_bound) * upper_bound) as usize;

        let mut table: Vec<[BlsScalar; 4]> = Vec::with_capacity(cap);

        for a in range.clone() {
            range
                .clone()
                .map(|b| {
                    let c = (a ^ b) % upper_bound;
                    [
                        BlsScalar::from(a),
                        BlsScalar::from(b),
                        BlsScalar::from(c),
                        BlsScalar::zero(),
                    ]
                })
                .for_each(|row| {
                    table.push(row);
                });
        }

        PlookupTable(table)
    }

    /// Function takes in two different usize numbers and checks the range
    /// between them, as well as computing the value of their product.
    /// These numbers require exponentiation outside, otherwise the range cannot
    /// start from zero, as 2^0 = 1.
    pub fn mul_table(lower_bound: u64, n: u8) -> Self {
        let upper_bound = 2u64.pow(n.into());

        let range = lower_bound..upper_bound;

        let cap = ((upper_bound - lower_bound) * upper_bound) as usize;

        let mut table: Vec<[BlsScalar; 4]> = Vec::with_capacity(cap);

        for a in range.clone() {
            range
                .clone()
                .map(|b| {
                    let c = (a * b) % upper_bound;
                    [
                        BlsScalar::from(a),
                        BlsScalar::from(b),
                        BlsScalar::from(c),
                        BlsScalar::zero(),
                    ]
                })
                .for_each(|row| {
                    table.push(row);
                });
        }

        PlookupTable(table)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constraint_system::StandardComposer;

    #[test]
    fn test_add_table() {
        let n = 4;

        let table = PlookupTable::add_table(0, n);

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

        let table = PlookupTable::xor_table(0, n);

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

        let table = PlookupTable::mul_table(0, n);

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
