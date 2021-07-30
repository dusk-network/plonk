// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Code taken from zcash repo and generalised as we do not have access to the
//! limbs
use core::mem;

macro_rules! bit_iterator {
    ($sty : ty, $name : ident) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $name<E> {
            // scalar is the slice of integers that wish to iterate over
            scalar: E,
            // num_of_total_bits represents the sum of all of the bits of each
            // integer If we have 2 u32s then the total number of bits will
            // be 32 * 2 = 64 bits
            num_of_total_bits: usize,
            // bit_len represents the bit length of each integer.
            // If we have a slice of u32s, then bit_len will be 32
            bit_len: usize,
        }

        impl<E: AsRef<[$sty]>> $name<E> {
            pub fn new(t: E) -> Self {
                let num_of_integers = t.as_ref().len();
                let num_of_total_bits = mem::size_of::<E>() * 8;
                let bit_len_of_each_integer =
                    num_of_total_bits / num_of_integers;
                $name {
                    scalar: t,
                    num_of_total_bits,
                    bit_len: bit_len_of_each_integer,
                }
            }
        }
        impl<E: AsRef<[$sty]>> Iterator for $name<E> {
            type Item = bool;

            fn next(&mut self) -> Option<bool> {
                if self.num_of_total_bits == 0 {
                    None
                } else {
                    self.num_of_total_bits -= 1;
                    let element_index = self.num_of_total_bits / self.bit_len;
                    let elements_bit = (self.num_of_total_bits % self.bit_len);
                    let number = self.scalar.as_ref()[element_index];

                    let bit = (number >> elements_bit) & 1;
                    Some(bit > 0)
                }
            }
        }
    };
}
bit_iterator!(u8, BitIterator8);

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use dusk_bls12_381::BlsScalar;
    use dusk_bytes::Serializable;

    #[test]
    fn test_bit_iterator8() {
        let mut a = BitIterator8::new(BlsScalar::one().to_bytes());
        let expected = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
        for e in expected.chars() {
            assert!(a.next().unwrap() == (e == '1'));
        }
        let _a_vec: Vec<_> = a.collect();
    }
}
