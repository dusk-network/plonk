// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::boxed::Box;
use alloc::vec::Vec;

use dusk_bytes::Serializable;
use hashbrown::HashMap;
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{
    DecompressorOxide, decompress, inflate_flags,
};

use super::{BlsScalar, Composer, Constraint, Error, Gate, Selector, Witness};

mod encoding;
mod hades;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressedConstraint {
    pub polynomial: usize,
    pub a: usize,
    pub b: usize,
    pub c: usize,
    pub d: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressedPolynomial {
    pub q_m: usize,
    pub q_l: usize,
    pub q_r: usize,
    pub q_o: usize,
    pub q_f: usize,
    pub q_c: usize,
    pub q_arith: usize,
    pub q_range: usize,
    pub q_logic: usize,
    pub q_fixed_group_add: usize,
    pub q_variable_group_add: usize,
}

impl CompressedPolynomial {
    fn scalar_indices(
        &self,
    ) -> [usize; CompressedCircuit::SELECTORS_PER_POLYNOMIAL] {
        [
            self.q_m,
            self.q_l,
            self.q_r,
            self.q_o,
            self.q_f,
            self.q_c,
            self.q_arith,
            self.q_range,
            self.q_logic,
            self.q_fixed_group_add,
            self.q_variable_group_add,
        ]
    }
}

fn scalar_map(hades_optimization: bool) -> HashMap<BlsScalar, usize> {
    let mut scalars: HashMap<BlsScalar, usize> = {
        [BlsScalar::zero(), BlsScalar::one(), -BlsScalar::one()]
            .into_iter()
            .enumerate()
            .map(|(i, s)| (s, i))
            .collect()
    };
    if hades_optimization {
        // assert we don't override a previously inserted constant
        for s in hades::constants() {
            let len = scalars.len();
            scalars.entry(s).or_insert(len);
        }
        for r in hades::mds() {
            for s in r {
                let len = scalars.len();
                scalars.entry(s).or_insert(len);
            }
        }
    }
    scalars
}

/// Inflates a raw deflate stream into at most `max_size` bytes.
///
/// Unlike `miniz_oxide::inflate::decompress_to_vec_with_limit`, this rejects
/// input left over after the end of the stream.
///
/// The loop copies the one inside `decompress_to_vec_with_limit`. No public
/// `miniz_oxide` function inflates into a size-limited vector and also reports
/// how much input it consumed. The functions that report consumed input fill
/// a buffer the caller sizes, so this loop grows that buffer up to `max_size`.
fn inflate_exact(compressed: &[u8], max_size: usize) -> Result<Vec<u8>, Error> {
    let flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let mut decompressor = Box::<DecompressorOxide>::default();
    let mut inflated =
        vec![0; compressed.len().saturating_mul(2).min(max_size)];
    let mut input = compressed;
    let mut written = 0;

    loop {
        let (status, consumed, produced) =
            decompress(&mut decompressor, input, &mut inflated, written, flags);
        written += produced;
        input = input
            .get(consumed..)
            .ok_or(Error::InvalidCompressedCircuit)?;

        match status {
            TINFLStatus::Done if input.is_empty() => {
                inflated.truncate(written);
                return Ok(inflated);
            }
            TINFLStatus::HasMoreOutput if inflated.len() < max_size => {
                // grow by at least one byte, so an empty buffer still grows
                let len = inflated.len().saturating_mul(2).max(1).min(max_size);
                inflated.resize(len, 0);
            }
            _ => return Err(Error::InvalidCompressedCircuit),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedCircuit {
    hades_optimization: bool,
    public_inputs: Vec<usize>,
    witnesses: usize,
    scalars: Vec<[u8; BlsScalar::SIZE]>,
    polynomials: Vec<CompressedPolynomial>,
    constraints: Vec<CompressedConstraint>,
}

impl CompressedCircuit {
    const SELECTORS_PER_POLYNOMIAL: usize = 11;
    const INDICES_PER_CONSTRAINT: usize = 5;

    fn validate_indices(&self, base_scalars: usize) -> Result<(), Error> {
        let scalar_count = base_scalars
            .checked_add(self.scalars.len())
            .ok_or(Error::InvalidCompressedCircuit)?;

        if self
            .public_inputs
            .iter()
            .any(|&i| i >= self.constraints.len())
            || self.public_inputs.windows(2).any(|w| w[0] >= w[1])
            || self.polynomials.iter().any(|polynomial| {
                polynomial
                    .scalar_indices()
                    .into_iter()
                    .any(|i| i >= scalar_count)
            })
            || self.constraints.iter().any(|constraint| {
                constraint.polynomial >= self.polynomials.len()
                    || [constraint.a, constraint.b, constraint.c, constraint.d]
                        .into_iter()
                        .any(|i| i >= self.witnesses)
            })
        {
            return Err(Error::InvalidCompressedCircuit);
        }

        Ok(())
    }

    pub fn from_composer(
        hades_optimization: bool,
        composer: Composer,
    ) -> Vec<u8> {
        let mut public_inputs: Vec<_> =
            composer.public_inputs.keys().copied().collect();
        public_inputs.sort();

        let witnesses = composer.witnesses.len();
        let polynomials = composer.constraints;

        let constraints = polynomials.into_iter();
        let mut scalars = scalar_map(hades_optimization);
        let base_scalars_len = scalars.len();
        let mut polynomials = HashMap::new();
        let constraints = constraints
            .map(
                |Gate {
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
                     a,
                     b,
                     c,
                     d,
                 }| {
                    let len = scalars.len();
                    let q_m = *scalars.entry(q_m).or_insert(len);
                    let len = scalars.len();
                    let q_l = *scalars.entry(q_l).or_insert(len);
                    let len = scalars.len();
                    let q_r = *scalars.entry(q_r).or_insert(len);
                    let len = scalars.len();
                    let q_o = *scalars.entry(q_o).or_insert(len);
                    let len = scalars.len();
                    let q_f = *scalars.entry(q_f).or_insert(len);
                    let len = scalars.len();
                    let q_c = *scalars.entry(q_c).or_insert(len);
                    let len = scalars.len();
                    let q_arith = *scalars.entry(q_arith).or_insert(len);
                    let len = scalars.len();
                    let q_range = *scalars.entry(q_range).or_insert(len);
                    let len = scalars.len();
                    let q_logic = *scalars.entry(q_logic).or_insert(len);
                    let len = scalars.len();
                    let q_fixed_group_add =
                        *scalars.entry(q_fixed_group_add).or_insert(len);
                    let len = scalars.len();
                    let q_variable_group_add =
                        *scalars.entry(q_variable_group_add).or_insert(len);
                    let polynomial = CompressedPolynomial {
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
                    };

                    let len = polynomials.len();
                    let polynomial =
                        *polynomials.entry(polynomial).or_insert(len);

                    CompressedConstraint {
                        polynomial,
                        a: a.index(),
                        b: b.index(),
                        c: c.index(),
                        d: d.index(),
                    }
                },
            )
            .collect();

        let scalars_map = scalars;
        let mut scalars = vec![[0u8; BlsScalar::SIZE]; scalars_map.len()];
        scalars_map
            .into_iter()
            .for_each(|(s, i)| scalars[i] = s.to_bytes());

        // clear the scalars that can be determiniscally reconstructed from the
        // scalar_map
        let scalars = scalars.split_off(base_scalars_len);

        let polynomials_map = polynomials;
        let mut polynomials =
            vec![CompressedPolynomial::default(); polynomials_map.len()];
        polynomials_map
            .into_iter()
            .for_each(|(p, i)| polynomials[i] = p);

        let compressed = Self {
            hades_optimization,
            public_inputs,
            witnesses,
            scalars,
            polynomials,
            constraints,
        };
        let mut buf = Vec::with_capacity(
            1 + compressed.scalars.len() * BlsScalar::SIZE
                + compressed.polynomials.len() * 88
                + compressed.constraints.len() * 40,
        );
        compressed.pack(&mut buf);
        miniz_oxide::deflate::compress_to_vec(&buf, 10)
    }

    fn remap_witness(
        composer: &mut Composer,
        witness_map: &mut HashMap<usize, Witness>,
        serialized: usize,
    ) -> Witness {
        if let Some(witness) = witness_map.get(&serialized) {
            *witness
        } else {
            let witness = composer.append_witness(BlsScalar::zero());
            witness_map.insert(serialized, witness);
            witness
        }
    }

    pub fn from_bytes(
        compressed: &[u8],
        max_constraints: usize,
    ) -> Result<Composer, Error> {
        let max_size = Self::packed_size_limit(max_constraints)?;
        let compressed = inflate_exact(compressed, max_size)?;
        let circuit = Self::unpack_bounded(&compressed, max_constraints)?;

        let scalar_map = scalar_map(circuit.hades_optimization);
        circuit.validate_indices(scalar_map.len())?;

        let Self {
            hades_optimization: _,
            public_inputs,
            witnesses: _,
            scalars,
            polynomials,
            constraints,
        } = circuit;

        let mut version_scalars = vec![BlsScalar::zero(); scalar_map.len()];
        scalar_map
            .into_iter()
            .for_each(|(s, i)| version_scalars[i] = s);
        for s in scalars {
            let scalar: BlsScalar = match BlsScalar::from_bytes(&s).into() {
                Some(scalar) => scalar,
                None => return Err(Error::BlsScalarMalformed),
            };
            version_scalars.push(scalar);
        }
        let scalars = version_scalars;

        // we use `uninitialized` because the decompressor will also contain the
        // dummy constraints, if they were part of the prover when encoding.
        let mut composer = Composer::uninitialized();
        let mut pi = 0;
        // Serialized witness indices are labels for wire-equality classes.
        // Allocate only labels referenced by gates so sparse or unused labels
        // cannot drive reconstruction work.
        let mut witness_map =
            HashMap::with_capacity(constraints.len().saturating_mul(4));

        for (
            i,
            CompressedConstraint {
                polynomial,
                a,
                b,
                c,
                d,
            },
        ) in constraints.into_iter().enumerate()
        {
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
            } = polynomials
                .get(polynomial)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;

            let q_m = scalars
                .get(q_m)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_l = scalars
                .get(q_l)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_r = scalars
                .get(q_r)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_o = scalars
                .get(q_o)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_f = scalars
                .get(q_f)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_c = scalars
                .get(q_c)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_arith = scalars
                .get(q_arith)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_range = scalars
                .get(q_range)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_logic = scalars
                .get(q_logic)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_fixed_group_add = scalars
                .get(q_fixed_group_add)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_variable_group_add = scalars
                .get(q_variable_group_add)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;

            let a = Self::remap_witness(&mut composer, &mut witness_map, a);
            let b = Self::remap_witness(&mut composer, &mut witness_map, b);
            let c = Self::remap_witness(&mut composer, &mut witness_map, c);
            let d = Self::remap_witness(&mut composer, &mut witness_map, d);

            let mut constraint = Constraint::default()
                .set(Selector::Multiplication, q_m)
                .set(Selector::Left, q_l)
                .set(Selector::Right, q_r)
                .set(Selector::Output, q_o)
                .set(Selector::Fourth, q_f)
                .set(Selector::Constant, q_c)
                .set(Selector::Arithmetic, q_arith)
                .set(Selector::Range, q_range)
                .set(Selector::Logic, q_logic)
                .set(Selector::GroupAddFixedBase, q_fixed_group_add)
                .set(Selector::GroupAddVariableBase, q_variable_group_add)
                .a(a)
                .b(b)
                .c(c)
                .d(d);

            if let Some(idx) = public_inputs.get(pi)
                && idx == &i
            {
                pi += 1;
                constraint = constraint.public(BlsScalar::zero());
            }

            composer.append_custom_gate(constraint);
        }

        Ok(composer)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use dusk_jubjub::{GENERATOR_EXTENDED, JubJubScalar};
    use rand_core::OsRng;

    use super::*;
    use crate::prelude::{Circuit, Compiler, PublicParameters};

    const MAX_CONSTRAINTS: usize = 2;

    fn circuit() -> CompressedCircuit {
        CompressedCircuit {
            hades_optimization: false,
            public_inputs: vec![0],
            witnesses: 1,
            scalars: Vec::new(),
            polynomials: vec![CompressedPolynomial::default()],
            constraints: vec![CompressedConstraint::default()],
        }
    }

    fn encode(circuit: &CompressedCircuit) -> Vec<u8> {
        let mut packed = Vec::new();
        circuit.pack(&mut packed);
        miniz_oxide::deflate::compress_to_vec(&packed, 10)
    }

    fn assert_invalid_without_panicking(circuit: &CompressedCircuit) {
        let base_scalars = scalar_map(circuit.hades_optimization).len();
        assert_eq!(
            circuit.validate_indices(base_scalars),
            Err(Error::InvalidCompressedCircuit),
            "semantic index validation must reject the circuit",
        );

        let encoded = encode(circuit);
        let result = catch_unwind(|| {
            CompressedCircuit::from_bytes(&encoded, MAX_CONSTRAINTS)
        });
        assert!(result.is_ok(), "checked decoding must not panic");
        assert!(matches!(
            result.unwrap(),
            Err(Error::InvalidCompressedCircuit)
        ));
    }

    #[test]
    fn valid_indices_are_accepted() {
        assert!(
            CompressedCircuit::from_bytes(&encode(&circuit()), MAX_CONSTRAINTS)
                .is_ok()
        );
    }

    fn assert_bounded_invalid_without_panicking(circuit: CompressedCircuit) {
        let encoded = encode(&circuit);
        let result = catch_unwind(|| {
            CompressedCircuit::from_bytes(&encoded, MAX_CONSTRAINTS)
        });
        assert!(result.is_ok(), "bounded decoding must not panic");
        assert!(matches!(
            result.unwrap(),
            Err(Error::InvalidCompressedCircuit)
        ));
    }

    #[test]
    fn capacity_limits_are_inclusive() {
        let mut circuit = circuit();
        circuit.public_inputs = vec![0, 1];
        circuit.constraints.push(CompressedConstraint::default());

        assert!(
            CompressedCircuit::from_bytes(&encode(&circuit), MAX_CONSTRAINTS)
                .is_ok()
        );
    }

    #[derive(Default)]
    struct SparseWitnessCircuit;

    impl Circuit for SparseWitnessCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            for _ in 0..37 {
                composer.append_witness(BlsScalar::zero());
            }
            Ok(())
        }
    }

    #[test]
    fn canonical_unused_witnesses_remain_compilable() {
        let pp = PublicParameters::setup(16, &mut OsRng).unwrap();

        let (direct_prover, direct_verifier) =
            Compiler::compile::<SparseWitnessCircuit>(&pp, b"sparse").unwrap();

        let compressed = SparseWitnessCircuit::compress().unwrap();
        let (compressed_prover, compressed_verifier) =
            Compiler::compile_with_compressed(&pp, b"sparse", &compressed)
                .unwrap();

        assert_eq!(direct_prover.to_bytes(), compressed_prover.to_bytes());
        assert_eq!(direct_verifier.to_bytes(), compressed_verifier.to_bytes());
    }

    #[test]
    fn sparse_witness_labels_do_not_drive_allocation() {
        let mut circuit = circuit();
        circuit.witnesses = 1_000_000;
        circuit.constraints[0].d = circuit.witnesses - 1;

        let composer =
            CompressedCircuit::from_bytes(&encode(&circuit), MAX_CONSTRAINTS)
                .unwrap();

        assert_eq!(composer.constraints.len(), 1);
        assert_eq!(composer.witnesses.len(), 2);
    }

    #[test]
    fn compiler_accepts_sparse_witness_labels() {
        let pp = PublicParameters::setup(8, &mut OsRng).unwrap();
        let mut circuit = circuit();
        circuit.witnesses = 1_000_000;
        circuit.constraints[0].d = circuit.witnesses - 1;
        let encoded = encode(&circuit);

        let result = catch_unwind(|| {
            Compiler::compile_with_compressed(&pp, b"bounded-circuit", &encoded)
        });
        assert!(result.is_ok(), "public compilation must not panic");
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn excessive_collection_counts_are_rejected_without_panicking() {
        let mut public_inputs = circuit();
        public_inputs.public_inputs = vec![0; MAX_CONSTRAINTS + 1];
        assert_bounded_invalid_without_panicking(public_inputs);

        let mut scalars = circuit();
        scalars.scalars = vec![
            [0; BlsScalar::SIZE];
            MAX_CONSTRAINTS
                * CompressedCircuit::SELECTORS_PER_POLYNOMIAL
                + 1
        ];
        assert_bounded_invalid_without_panicking(scalars);

        let mut polynomials = circuit();
        polynomials.polynomials =
            vec![CompressedPolynomial::default(); MAX_CONSTRAINTS + 1];
        assert_bounded_invalid_without_panicking(polynomials);

        let mut constraints = circuit();
        constraints.constraints =
            vec![CompressedConstraint::default(); MAX_CONSTRAINTS + 1];
        assert_bounded_invalid_without_panicking(constraints);
    }

    #[test]
    fn inflated_size_is_rejected_without_panicking() {
        let max_size =
            CompressedCircuit::packed_size_limit(MAX_CONSTRAINTS).unwrap();
        let compressed =
            miniz_oxide::deflate::compress_to_vec(&vec![0; max_size + 1], 10);

        let result = catch_unwind(|| {
            CompressedCircuit::from_bytes(&compressed, MAX_CONSTRAINTS)
        });
        assert!(result.is_ok(), "bounded decompression must not panic");
        assert!(matches!(
            result.unwrap(),
            Err(Error::InvalidCompressedCircuit)
        ));
    }

    #[test]
    fn trailing_bytes_after_deflate_stream_are_rejected() {
        let encoded = encode(&circuit());

        for suffix in [&[0][..], &[0xff; 32], &encoded[..]] {
            let mut padded = encoded.clone();
            padded.extend_from_slice(suffix);

            assert!(matches!(
                CompressedCircuit::from_bytes(&padded, MAX_CONSTRAINTS),
                Err(Error::InvalidCompressedCircuit)
            ));
        }
    }

    #[test]
    fn invalid_witness_indices_are_rejected_without_panicking() {
        let setters: [fn(&mut CompressedConstraint, usize); 4] = [
            |constraint, invalid| constraint.a = invalid,
            |constraint, invalid| constraint.b = invalid,
            |constraint, invalid| constraint.c = invalid,
            |constraint, invalid| constraint.d = invalid,
        ];

        for set_invalid in setters {
            let mut circuit = circuit();
            set_invalid(&mut circuit.constraints[0], circuit.witnesses);
            assert_invalid_without_panicking(&circuit);
        }
    }

    #[test]
    fn invalid_polynomial_index_is_rejected_without_panicking() {
        let mut circuit = circuit();
        circuit.constraints[0].polynomial = circuit.polynomials.len();
        assert_invalid_without_panicking(&circuit);
    }

    #[test]
    fn invalid_scalar_indices_are_rejected_without_panicking() {
        let setters: [fn(&mut CompressedPolynomial, usize);
            CompressedCircuit::SELECTORS_PER_POLYNOMIAL] = [
            |polynomial, invalid| polynomial.q_m = invalid,
            |polynomial, invalid| polynomial.q_l = invalid,
            |polynomial, invalid| polynomial.q_r = invalid,
            |polynomial, invalid| polynomial.q_o = invalid,
            |polynomial, invalid| polynomial.q_f = invalid,
            |polynomial, invalid| polynomial.q_c = invalid,
            |polynomial, invalid| polynomial.q_arith = invalid,
            |polynomial, invalid| polynomial.q_range = invalid,
            |polynomial, invalid| polynomial.q_logic = invalid,
            |polynomial, invalid| polynomial.q_fixed_group_add = invalid,
            |polynomial, invalid| polynomial.q_variable_group_add = invalid,
        ];

        for set_invalid in setters {
            let mut circuit = circuit();
            let invalid = scalar_map(false).len();
            set_invalid(&mut circuit.polynomials[0], invalid);
            assert_invalid_without_panicking(&circuit);
        }
    }

    #[test]
    fn invalid_public_input_indices_are_rejected_without_panicking() {
        let mut out_of_range = circuit();
        out_of_range.public_inputs = vec![1];
        assert_invalid_without_panicking(&out_of_range);

        for public_inputs in [vec![0, 0], vec![1, 0]] {
            let mut circuit = circuit();
            circuit.constraints.push(CompressedConstraint::default());
            circuit.public_inputs = public_inputs;
            assert_invalid_without_panicking(&circuit);
        }
    }

    // Circuit IDs hash the compressed bytes, so the msgpack encoding must not
    // change. Each case pins the full packed bytes and decodes them back.
    fn assert_packed_encoding(
        circuit: &CompressedCircuit,
        expected: &[u8],
        max_constraints: usize,
    ) {
        let mut packed = Vec::new();
        circuit.pack(&mut packed);
        assert_eq!(packed, expected);

        let unpacked =
            CompressedCircuit::unpack_bounded(expected, max_constraints)
                .unwrap();
        assert_eq!(&unpacked, circuit);
    }

    #[test]
    fn packed_encoding_is_pinned() {
        // `true`, an array16 header, every integer width up to uint32 and both
        // encodings of a scalar byte.
        let mut scalar = [0x2a; BlsScalar::SIZE];
        scalar[..4].copy_from_slice(&[0x00, 0x7f, 0x80, 0xff]);
        let circuit = CompressedCircuit {
            hades_optimization: true,
            public_inputs: (0..16).collect(),
            witnesses: 0x1234,
            scalars: vec![scalar],
            polynomials: vec![CompressedPolynomial {
                q_m: 0,
                q_l: 127,
                q_r: 128,
                q_o: 255,
                q_f: 256,
                q_c: 65535,
                q_arith: 65536,
                q_range: u32::MAX as usize,
                q_logic: 1,
                q_fixed_group_add: 2,
                q_variable_group_add: 3,
            }],
            constraints: vec![CompressedConstraint {
                polynomial: 4,
                a: 5,
                b: 6,
                c: 7,
                d: 8,
            }],
        };
        let expected = [
            // hades_optimization
            &[0xc3][..],
            // public_inputs
            &[0xdc, 0x00, 0x10],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            &[0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            // witnesses
            &[0xcd, 0x12, 0x34],
            // scalars
            &[0x91, 0x00, 0x7f, 0xcc, 0x80, 0xcc, 0xff],
            &[0x2a; BlsScalar::SIZE - 4],
            // polynomials
            &[0x91, 0x00, 0x7f, 0xcc, 0x80, 0xcc, 0xff, 0xcd, 0x01, 0x00],
            &[0xcd, 0xff, 0xff, 0xce, 0x00, 0x01, 0x00, 0x00],
            &[0xce, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03],
            // constraints
            &[0x91, 0x04, 0x05, 0x06, 0x07, 0x08],
        ]
        .concat();
        assert_packed_encoding(&circuit, &expected, 16);

        // `false` and empty fixarray headers.
        let empty = CompressedCircuit {
            hades_optimization: false,
            public_inputs: Vec::new(),
            witnesses: 0,
            scalars: Vec::new(),
            polynomials: Vec::new(),
            constraints: Vec::new(),
        };
        assert_packed_encoding(
            &empty,
            &[0xc2, 0x90, 0x00, 0x90, 0x90, 0x90],
            0,
        );

        // The longest fixarray header.
        let fifteen = CompressedCircuit {
            public_inputs: (0..15).collect(),
            ..empty.clone()
        };
        let expected = [
            &[0xc2, 0x9f][..],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            &[0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e],
            &[0x00, 0x90, 0x90, 0x90],
        ]
        .concat();
        assert_packed_encoding(&fifteen, &expected, 15);

        // An array32 header.
        let len = usize::from(u16::MAX) + 1;
        let long = CompressedCircuit {
            constraints: vec![CompressedConstraint::default(); len],
            ..empty.clone()
        };
        let expected = [
            &[0xc2, 0x90, 0x00, 0x90, 0x90, 0xdd, 0x00, 0x01, 0x00, 0x00][..],
            &vec![0x00; len * CompressedCircuit::INDICES_PER_CONSTRAINT],
        ]
        .concat();
        assert_packed_encoding(&long, &expected, len);

        // uint64, which only a 64-bit `usize` reaches.
        #[cfg(target_pointer_width = "64")]
        {
            let wide = CompressedCircuit {
                witnesses: u32::MAX as usize + 1,
                constraints: vec![CompressedConstraint {
                    d: usize::MAX,
                    ..CompressedConstraint::default()
                }],
                ..empty
            };
            let expected = [
                &[0xc2, 0x90][..],
                &[0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
                &[0x90, 0x90, 0x91, 0x00, 0x00, 0x00, 0x00],
                &[0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ]
            .concat();
            assert_packed_encoding(&wide, &expected, 1);
        }
    }

    /// A compressed circuit stores a scalar of the Hades dictionary as its
    /// index, so every compressed circuit depends on the dictionary's values,
    /// not only on its size, which is all `compressed_circuit_is_pinned` sees.
    #[test]
    fn hades_dictionary_is_pinned() {
        const DICTIONARY_BLAKE2B: &str = "aba602ed119b67d26dfac88e74d9e6fc\
            b7164bb994aaa0544142aa5aad1cfcc3546671be1a197ba31259196394e061a2\
            8f59b7f2105ad8ebd7a00f9d875bcd3e";

        let mut state = blake2b_simd::State::new();
        hades::constants()
            .iter()
            .chain(hades::mds().iter().flatten())
            .for_each(|scalar| {
                state.update(&scalar.to_bytes());
            });

        assert_eq!(state.finalize().to_hex().as_str(), DICTIONARY_BLAKE2B);
    }

    #[derive(Default)]
    struct PinnedCircuit;

    impl Circuit for PinnedCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let a = composer.append_witness(BlsScalar::from(3));
            let b = composer.append_public(BlsScalar::from(5));

            let constraint =
                Constraint::new().left(2).right(7).constant(11).a(a).b(b);
            let sum = composer.gate_add(constraint);
            let constraint = Constraint::new().mult(13).a(sum).b(a);
            let product = composer.gate_mul(constraint);

            composer.component_range_bits::<16>(product);
            composer.append_logic_xor::<4>(a, b);

            let scalar = composer.append_witness(JubJubScalar::from(9u64));
            let point =
                composer.component_mul_generator(scalar, GENERATOR_EXTENDED)?;
            composer.component_add_point(point, point);

            Ok(())
        }
    }

    #[test]
    fn compressed_circuit_is_pinned() {
        const PACKED_LEN: usize = 47596;
        const PACKED_BLAKE2B: &str = "05b0f486fe4fda64b7d9f2b12533d037\
            bec546f8dc2905092b3eee142026f0b352f869dc763b621291cb67d3f69e1326\
            9f688e654848f62b1207f64b29de515d";

        let compressed = PinnedCircuit::compress().unwrap();
        let packed =
            miniz_oxide::inflate::decompress_to_vec(&compressed).unwrap();

        assert_eq!(packed.len(), PACKED_LEN);
        assert_eq!(
            blake2b_simd::blake2b(&packed).to_hex().as_str(),
            PACKED_BLAKE2B
        );
        assert_eq!(
            compressed,
            miniz_oxide::deflate::compress_to_vec(&packed, 10)
        );

        // The pin covers every selector, stored scalars and public inputs.
        let circuit =
            CompressedCircuit::unpack_bounded(&packed, PACKED_LEN).unwrap();
        for selector in 0..CompressedCircuit::SELECTORS_PER_POLYNOMIAL {
            assert!(
                circuit
                    .polynomials
                    .iter()
                    .any(|p| p.scalar_indices()[selector] != 0)
            );
        }
        assert!(!circuit.scalars.is_empty());
        assert!(!circuit.public_inputs.is_empty());
    }
}
