use std::mem;
// Code taken from zcash repo and generalised as we do not have access to the limbs
macro_rules! bit_iterator {
    ($sty : ty, $name : ident) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $name<E> {
            // scalar is the slice of integers that wish to iterate over
            scalar: E,
            // num_of_total_bits represents the sum of all of the bits of each integer
            // If we have 2 u32s then the total number of bits will be 32 * 2 = 64 bits
            num_of_total_bits: usize,
            // bit_len represents the bit length of each integer.
            // If we have a slice of u32s, then bit_len will be 32
            bit_len: usize,
        }

        impl<E: AsRef<[$sty]>> $name<E> {
            pub fn new(t: E) -> Self {
                let num_of_integers = t.as_ref().len();
                let num_of_total_bits = mem::size_of::<E>() * 8;
                let bit_len_of_each_integer = num_of_total_bits / num_of_integers;
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
bit_iterator!(u16, BitIterator16);
bit_iterator!(u32, BitIterator32);
bit_iterator!(u64, BitIterator64);
bit_iterator!(u128, BitIterator128);

mod test {
    use super::*;
    #[test]
    fn test_bit_iterator64() {
        let mut a = BitIterator64::new([0xa953d79b83f6ab59, 0x6dea2059e200bd39]);
        let expected = "01101101111010100010000001011001111000100000000010111101001110011010100101010011110101111001101110000011111101101010101101011001";
        for e in expected.chars() {
            assert!(a.next().unwrap() == (e == '1'));
        }
    }
    use bls12_381::Scalar;
    #[test]
    fn test_bit_iterator8() {
        let mut a = BitIterator8::new(Scalar::one().to_bytes());
        let expected = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
        for e in expected.chars() {
            assert!(a.next().unwrap() == (e == '1'));
        }
        let a_vec: Vec<_> = a.collect();
    }
}
