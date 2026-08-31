// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Code taken from zcash repo and generalized as we do not have access to the
//! limbs

#[derive(Debug, Clone, Copy)]
pub struct BitIterator8<E> {
    // scalar is the byte slice that we wish to iterate over
    scalar: E,
    // num_of_total_bits represents the sum of all of the bits of each byte
    num_of_total_bits: usize,
}

impl<E: AsRef<[u8]>> BitIterator8<E> {
    pub fn new(t: E) -> Self {
        let num_of_total_bits = t.as_ref().len() * 8;
        BitIterator8 {
            scalar: t,
            num_of_total_bits,
        }
    }
}
impl<E: AsRef<[u8]>> Iterator for BitIterator8<E> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.num_of_total_bits == 0 {
            None
        } else {
            self.num_of_total_bits -= 1;
            let element_index = self.num_of_total_bits / 8;
            let elements_bit = self.num_of_total_bits % 8;
            let number = self.scalar.as_ref()[element_index];

            let bit = (number >> elements_bit) & 1;
            Some(bit > 0)
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use alloc::vec::Vec;

    use dusk_bls12_381::BlsScalar;

    use super::*;

    #[test]
    fn test_bit_iterator8() {
        let mut a = BitIterator8::new(BlsScalar::one().to_bytes());
        let expected = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
        for e in expected.chars() {
            assert_eq!(a.next().unwrap(), (e == '1'));
        }
        let _a_vec: Vec<_> = a.collect();
    }

    #[test]
    fn test_bit_iterator8_vec() {
        let bits: Vec<_> = BitIterator8::new(Vec::from([0x01, 0x80])).collect();

        assert_eq!(bits.len(), 16);
        assert!(bits[0]);
        assert!(bits[15]);
        assert_eq!(bits.iter().filter(|bit| **bit).count(), 2);
    }
}
