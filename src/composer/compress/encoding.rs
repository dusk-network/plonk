// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The packed encoding of a [`CompressedCircuit`].
//!
//! The encoding is a subset of MessagePack. A struct is its fields in
//! declaration order, with no header. A `Vec` is an array header followed by
//! its elements. A `[u8; N]` is `N` unsigned integers, with no header.

use alloc::vec::Vec;

use dusk_bytes::Serializable;

use super::{
    BlsScalar, CompressedCircuit, CompressedConstraint, CompressedPolynomial,
    Error,
};

// MessagePack format tags.
const POSITIVE_FIXINT_MAX: u8 = 0x7f;
const FIXARRAY: u8 = 0x90;
const FIXARRAY_LEN_MASK: u8 = 0x0f;
const FIXARRAY_MAX: u8 = FIXARRAY | FIXARRAY_LEN_MASK;
const NEVER_USED: u8 = 0xc1;
const FALSE: u8 = 0xc2;
const TRUE: u8 = 0xc3;
const UINT8: u8 = 0xcc;
const UINT16: u8 = 0xcd;
const UINT32: u8 = 0xce;
const UINT64: u8 = 0xcf;
const ARRAY16: u8 = 0xdc;
const ARRAY32: u8 = 0xdd;

impl CompressedCircuit {
    // Upper bounds of the packed sizes. A `usize` is bounded by uint64, the
    // widest form the decoder accepts, on every target.
    const PACKED_BOOL_BYTES: usize = 1;
    const PACKED_USIZE_BYTES: usize = 1 + size_of::<u64>();
    const PACKED_U8_BYTES: usize = 1 + size_of::<u8>();
    const PACKED_VECTOR_HEADER_BYTES: usize = 1 + size_of::<u32>();
    const PACKED_FIXED_BYTES: usize = Self::PACKED_BOOL_BYTES
        + Self::PACKED_USIZE_BYTES
        + 4 * Self::PACKED_VECTOR_HEADER_BYTES;
    const PACKED_BYTES_PER_CONSTRAINT: usize = Self::PACKED_USIZE_BYTES
        + Self::SELECTORS_PER_POLYNOMIAL
            * BlsScalar::SIZE
            * Self::PACKED_U8_BYTES
        + Self::SELECTORS_PER_POLYNOMIAL * Self::PACKED_USIZE_BYTES
        + Self::INDICES_PER_CONSTRAINT * Self::PACKED_USIZE_BYTES;

    /// Appends the packed circuit to `buf`.
    pub(super) fn pack(&self, buf: &mut Vec<u8>) {
        pack_bool(buf, self.hades_optimization);
        pack_array(buf, &self.public_inputs, |buf, &i| pack_usize(buf, i));
        pack_usize(buf, self.witnesses);
        pack_array(buf, &self.scalars, pack_scalar);
        pack_array(buf, &self.polynomials, pack_polynomial);
        pack_array(buf, &self.constraints, pack_constraint);
    }

    /// Returns the largest packed size of a circuit with at most
    /// `max_constraints` constraints.
    pub(super) fn packed_size_limit(
        max_constraints: usize,
    ) -> Result<usize, Error> {
        max_constraints
            .checked_mul(Self::PACKED_BYTES_PER_CONSTRAINT)
            .and_then(|size| size.checked_add(Self::PACKED_FIXED_BYTES))
            .ok_or(Error::InvalidCompressedCircuit)
    }

    /// Decodes a packed circuit, bounding every collection by
    /// `max_constraints` before it is allocated.
    pub(super) fn unpack_bounded(
        packed: &[u8],
        max_constraints: usize,
    ) -> Result<Self, Error> {
        let mut reader = PackedCircuitReader::new(packed);
        let max_scalars = max_constraints
            .checked_mul(Self::SELECTORS_PER_POLYNOMIAL)
            .ok_or(Error::InvalidCompressedCircuit)?;

        let circuit = Self {
            hades_optimization: reader.unpack_bool()?,
            public_inputs: reader.unpack_vec(
                max_constraints,
                PackedCircuitReader::unpack_usize,
            )?,
            witnesses: reader.unpack_usize()?,
            scalars: reader
                .unpack_vec(max_scalars, PackedCircuitReader::unpack_scalar)?,
            polynomials: reader.unpack_vec(
                max_constraints,
                PackedCircuitReader::unpack_polynomial,
            )?,
            constraints: reader.unpack_vec(
                max_constraints,
                PackedCircuitReader::unpack_constraint,
            )?,
        };

        if !reader.is_empty() {
            return Err(Error::InvalidCompressedCircuit);
        }

        Ok(circuit)
    }
}

fn pack_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(if value { TRUE } else { FALSE });
}

fn pack_u8(buf: &mut Vec<u8>, value: u8) {
    if value <= POSITIVE_FIXINT_MAX {
        buf.push(value);
    } else {
        buf.extend([UINT8, value]);
    }
}

fn pack_usize(buf: &mut Vec<u8>, value: usize) {
    if let Ok(value) = u8::try_from(value) {
        pack_u8(buf, value);
    } else if let Ok(value) = u16::try_from(value) {
        buf.push(UINT16);
        buf.extend(value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        buf.push(UINT32);
        buf.extend(value.to_be_bytes());
    } else {
        // `usize` is at most 64 bits wide on every supported target.
        buf.push(UINT64);
        buf.extend((value as u64).to_be_bytes());
    }
}

fn pack_array_len(buf: &mut Vec<u8>, len: usize) {
    if let Ok(len) = u8::try_from(len)
        && len <= FIXARRAY_LEN_MASK
    {
        buf.push(FIXARRAY | len);
    } else if let Ok(len) = u16::try_from(len) {
        buf.push(ARRAY16);
        buf.extend(len.to_be_bytes());
    } else if let Ok(len) = u32::try_from(len) {
        buf.push(ARRAY32);
        buf.extend(len.to_be_bytes());
    } else {
        // MessagePack has no longer array. The reserved tag makes the decoder
        // reject the circuit instead of misreading it.
        buf.push(NEVER_USED);
    }
}

fn pack_array<T>(
    buf: &mut Vec<u8>,
    items: &[T],
    pack_item: impl Fn(&mut Vec<u8>, &T),
) {
    pack_array_len(buf, items.len());
    for item in items {
        pack_item(buf, item);
    }
}

fn pack_scalar(buf: &mut Vec<u8>, scalar: &[u8; BlsScalar::SIZE]) {
    for &byte in scalar {
        pack_u8(buf, byte);
    }
}

fn pack_polynomial(buf: &mut Vec<u8>, polynomial: &CompressedPolynomial) {
    let CompressedPolynomial {
        q_m,
        q_l,
        q_r,
        q_o,
        q_f,
        q_c,
        q_arith,
        q_range,
        q_logic,
        q_fixed_group_add,
        q_variable_group_add,
    } = *polynomial;
    for index in [
        q_m,
        q_l,
        q_r,
        q_o,
        q_f,
        q_c,
        q_arith,
        q_range,
        q_logic,
        q_fixed_group_add,
        q_variable_group_add,
    ] {
        pack_usize(buf, index);
    }
}

fn pack_constraint(buf: &mut Vec<u8>, constraint: &CompressedConstraint) {
    let CompressedConstraint {
        polynomial,
        a,
        b,
        c,
        d,
    } = *constraint;
    for index in [polynomial, a, b, c, d] {
        pack_usize(buf, index);
    }
}

struct PackedCircuitReader<'a> {
    remaining: &'a [u8],
}

impl<'a> PackedCircuitReader<'a> {
    fn new(packed: &'a [u8]) -> Self {
        Self { remaining: packed }
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn unpack_bool(&mut self) -> Result<bool, Error> {
        match self.take_byte()? {
            FALSE => Ok(false),
            TRUE => Ok(true),
            _ => Err(Error::InvalidCompressedCircuit),
        }
    }

    fn unpack_u8(&mut self) -> Result<u8, Error> {
        match self.take_byte()? {
            tag @ 0..=POSITIVE_FIXINT_MAX => Ok(tag),
            UINT8 => self.take_byte(),
            _ => Err(Error::InvalidCompressedCircuit),
        }
    }

    // Accepts every width, also when a shorter one fits the value.
    fn unpack_usize(&mut self) -> Result<usize, Error> {
        let value = match self.take_byte()? {
            tag @ 0..=POSITIVE_FIXINT_MAX => u64::from(tag),
            UINT8 => u64::from(self.take_byte()?),
            UINT16 => u64::from(u16::from_be_bytes(self.take_array()?)),
            UINT32 => u64::from(u32::from_be_bytes(self.take_array()?)),
            UINT64 => u64::from_be_bytes(self.take_array()?),
            _ => return Err(Error::InvalidCompressedCircuit),
        };
        usize::try_from(value).map_err(|_| Error::InvalidCompressedCircuit)
    }

    fn unpack_scalar(&mut self) -> Result<[u8; BlsScalar::SIZE], Error> {
        let mut scalar = [0; BlsScalar::SIZE];
        for byte in &mut scalar {
            *byte = self.unpack_u8()?;
        }
        Ok(scalar)
    }

    fn unpack_polynomial(&mut self) -> Result<CompressedPolynomial, Error> {
        Ok(CompressedPolynomial {
            q_m: self.unpack_usize()?,
            q_l: self.unpack_usize()?,
            q_r: self.unpack_usize()?,
            q_o: self.unpack_usize()?,
            q_f: self.unpack_usize()?,
            q_c: self.unpack_usize()?,
            q_arith: self.unpack_usize()?,
            q_range: self.unpack_usize()?,
            q_logic: self.unpack_usize()?,
            q_fixed_group_add: self.unpack_usize()?,
            q_variable_group_add: self.unpack_usize()?,
        })
    }

    fn unpack_constraint(&mut self) -> Result<CompressedConstraint, Error> {
        Ok(CompressedConstraint {
            polynomial: self.unpack_usize()?,
            a: self.unpack_usize()?,
            b: self.unpack_usize()?,
            c: self.unpack_usize()?,
            d: self.unpack_usize()?,
        })
    }

    fn unpack_vec<T>(
        &mut self,
        max_len: usize,
        unpack_item: fn(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let len = self.unpack_array_len()?;
        if len > max_len {
            return Err(Error::InvalidCompressedCircuit);
        }

        (0..len).map(|_| unpack_item(self)).collect()
    }

    fn unpack_array_len(&mut self) -> Result<usize, Error> {
        let len = match self.take_byte()? {
            tag @ FIXARRAY..=FIXARRAY_MAX => u32::from(tag & FIXARRAY_LEN_MASK),
            ARRAY16 => u32::from(u16::from_be_bytes(self.take_array()?)),
            ARRAY32 => u32::from_be_bytes(self.take_array()?),
            _ => return Err(Error::InvalidCompressedCircuit),
        };
        usize::try_from(len).map_err(|_| Error::InvalidCompressedCircuit)
    }

    fn take_byte(&mut self) -> Result<u8, Error> {
        let [byte] = self.take_array()?;
        Ok(byte)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (bytes, remaining) = self
            .remaining
            .split_first_chunk()
            .ok_or(Error::InvalidCompressedCircuit)?;
        self.remaining = remaining;
        Ok(*bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_constraint_fits_derived_bound() {
        let polynomial = CompressedPolynomial {
            q_m: usize::MAX,
            q_l: usize::MAX,
            q_r: usize::MAX,
            q_o: usize::MAX,
            q_f: usize::MAX,
            q_c: usize::MAX,
            q_arith: usize::MAX,
            q_range: usize::MAX,
            q_logic: usize::MAX,
            q_fixed_group_add: usize::MAX,
            q_variable_group_add: usize::MAX,
        };
        let constraint = CompressedConstraint {
            polynomial: usize::MAX,
            a: usize::MAX,
            b: usize::MAX,
            c: usize::MAX,
            d: usize::MAX,
        };
        let mut packed = Vec::new();
        pack_usize(&mut packed, usize::MAX);
        for _ in 0..CompressedCircuit::SELECTORS_PER_POLYNOMIAL {
            pack_scalar(&mut packed, &[u8::MAX; BlsScalar::SIZE]);
        }
        pack_polynomial(&mut packed, &polynomial);
        pack_constraint(&mut packed, &constraint);
        assert!(packed.len() <= CompressedCircuit::PACKED_BYTES_PER_CONSTRAINT);
        let worst = CompressedCircuit {
            hades_optimization: true,
            public_inputs: vec![usize::MAX],
            witnesses: usize::MAX,
            scalars: vec![
                [u8::MAX; BlsScalar::SIZE];
                CompressedCircuit::SELECTORS_PER_POLYNOMIAL
            ],
            polynomials: vec![polynomial],
            constraints: vec![constraint],
        };
        packed.clear();
        worst.pack(&mut packed);
        assert!(
            packed.len() <= CompressedCircuit::packed_size_limit(1).unwrap()
        );
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            packed.len()
                + 4 * (CompressedCircuit::PACKED_VECTOR_HEADER_BYTES - 1),
            CompressedCircuit::packed_size_limit(1).unwrap()
        );

        packed.clear();
        pack_array_len(&mut packed, usize::from(u16::MAX) + 1);
        assert_eq!(packed, [0xdd, 0, 1, 0, 0]);
        assert_eq!(packed.len(), CompressedCircuit::PACKED_VECTOR_HEADER_BYTES);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn oversized_array_is_rejected() {
        let mut packed = Vec::new();
        pack_array_len(&mut packed, u32::MAX as usize + 1);
        assert_eq!(packed, [NEVER_USED]);
        assert_eq!(
            PackedCircuitReader::new(&packed).unpack_array_len(),
            Err(Error::InvalidCompressedCircuit)
        );
    }

    #[test]
    fn raw_array_headers_are_bounded() {
        for bytes in [&[0xc0][..], &[], &[0xdc], &[0xdc, 0], &[0xdd, 0, 0, 0]] {
            assert!(matches!(
                PackedCircuitReader::new(bytes)
                    .unpack_vec(2, PackedCircuitReader::unpack_usize),
                Err(Error::InvalidCompressedCircuit)
            ));
        }
        let mut reader = PackedCircuitReader::new(&[0xdd, 0, 0, 0, 2, 0, 1]);
        assert_eq!(
            reader
                .unpack_vec(2, PackedCircuitReader::unpack_usize)
                .unwrap(),
            vec![0, 1]
        );
        assert!(reader.is_empty());
    }

    #[test]
    fn wider_integer_forms_decode_to_the_same_value() {
        for bytes in [
            &[0x05][..],
            &[0xcc, 0x05],
            &[0xcd, 0x00, 0x05],
            &[0xce, 0x00, 0x00, 0x00, 0x05],
            &[0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05],
        ] {
            let mut reader = PackedCircuitReader::new(bytes);
            assert_eq!(reader.unpack_usize(), Ok(5));
            assert!(reader.is_empty());
        }

        let mut reader = PackedCircuitReader::new(&[0xcc, 0x05]);
        assert_eq!(reader.unpack_u8(), Ok(5));
        assert!(reader.is_empty());
    }

    #[test]
    fn uint64_beyond_usize_is_rejected() {
        let mut reader = PackedCircuitReader::new(&[
            0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        let value = reader.unpack_usize();
        #[cfg(target_pointer_width = "64")]
        assert_eq!(value, Ok(u32::MAX as usize + 1));
        #[cfg(target_pointer_width = "32")]
        assert_eq!(value, Err(Error::InvalidCompressedCircuit));
    }

    #[test]
    fn wrong_tags_are_rejected() {
        let unpack_bool = |bytes| PackedCircuitReader::new(bytes).unpack_bool();
        for bytes in [&[0xc0][..], &[0x00], &[0x01]] {
            assert_eq!(
                unpack_bool(bytes),
                Err(Error::InvalidCompressedCircuit)
            );
        }

        let unpack_u8 = |bytes| PackedCircuitReader::new(bytes).unpack_u8();
        for bytes in [&[0xc0][..], &[0xcd, 0x00, 0x01], &[0xe0], &[0xff]] {
            assert_eq!(unpack_u8(bytes), Err(Error::InvalidCompressedCircuit));
        }

        let unpack_usize =
            |bytes| PackedCircuitReader::new(bytes).unpack_usize();
        for bytes in [&[0xc0][..], &[0xc3], &[0xd0, 0x01], &[0xe0], &[0xff]] {
            assert_eq!(
                unpack_usize(bytes),
                Err(Error::InvalidCompressedCircuit)
            );
        }
    }

    #[test]
    fn short_buffers_are_rejected() {
        assert_eq!(
            PackedCircuitReader::new(&[]).unpack_bool(),
            Err(Error::InvalidCompressedCircuit)
        );
        for bytes in [&[][..], &[0xcc]] {
            assert_eq!(
                PackedCircuitReader::new(bytes).unpack_u8(),
                Err(Error::InvalidCompressedCircuit)
            );
        }
        for bytes in [
            &[][..],
            &[0xcc],
            &[0xcd, 0x00],
            &[0xce, 0x00, 0x00, 0x00],
            &[0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ] {
            assert_eq!(
                PackedCircuitReader::new(bytes).unpack_usize(),
                Err(Error::InvalidCompressedCircuit)
            );
        }
        assert_eq!(
            PackedCircuitReader::new(&[0x00; BlsScalar::SIZE - 1])
                .unpack_scalar(),
            Err(Error::InvalidCompressedCircuit)
        );
        assert_eq!(
            PackedCircuitReader::new(&[0x00; 10]).unpack_polynomial(),
            Err(Error::InvalidCompressedCircuit)
        );
        assert_eq!(
            PackedCircuitReader::new(&[0x00; 4]).unpack_constraint(),
            Err(Error::InvalidCompressedCircuit)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let circuit = CompressedCircuit {
            hades_optimization: false,
            public_inputs: Vec::new(),
            witnesses: 0,
            scalars: Vec::new(),
            polynomials: Vec::new(),
            constraints: Vec::new(),
        };
        let mut packed = Vec::new();
        circuit.pack(&mut packed);
        assert_eq!(CompressedCircuit::unpack_bounded(&packed, 0), Ok(circuit));

        packed.push(0x00);
        assert_eq!(
            CompressedCircuit::unpack_bounded(&packed, 0),
            Err(Error::InvalidCompressedCircuit)
        );
    }
}
