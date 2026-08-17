// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_bytes::Serializable;
use hashbrown::HashMap;
use msgpacker::{MsgPacker, Packable, Unpackable};

use super::{BlsScalar, Composer, Constraint, Error, Gate, Selector, Witness};

mod hades;

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, MsgPacker,
)]
pub struct CompressedConstraint {
    pub polynomial: usize,
    pub a: usize,
    pub b: usize,
    pub c: usize,
    pub d: usize,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, MsgPacker,
)]
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
    fn scalar_indices(&self) -> [usize; 11] {
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

#[derive(Debug, Clone, PartialEq, Eq, MsgPacker)]
pub struct CompressedCircuit {
    hades_optimization: bool,
    public_inputs: Vec<usize>,
    witnesses: usize,
    scalars: Vec<[u8; BlsScalar::SIZE]>,
    polynomials: Vec<CompressedPolynomial>,
    constraints: Vec<CompressedConstraint>,
}

impl CompressedCircuit {
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

    pub fn from_bytes(compressed: &[u8]) -> Result<Composer, Error> {
        let compressed = miniz_oxide::inflate::decompress_to_vec(compressed)
            .map_err(|_| Error::InvalidCompressedCircuit)?;
        let (consumed, circuit) = Self::unpack(&compressed)
            .map_err(|_| Error::InvalidCompressedCircuit)?;
        if consumed != compressed.len() {
            return Err(Error::InvalidCompressedCircuit);
        }

        let scalar_map = scalar_map(circuit.hades_optimization);
        circuit.validate_indices(scalar_map.len())?;

        let Self {
            hades_optimization: _,
            public_inputs,
            witnesses,
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
        (0..witnesses).for_each(|_| {
            composer.append_witness(BlsScalar::zero());
        });

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

            let a = Witness::new(a);
            let b = Witness::new(b);
            let c = Witness::new(c);
            let d = Witness::new(d);

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

            if let Some(idx) = public_inputs.get(pi) {
                if idx == &i {
                    pi += 1;
                    constraint = constraint.public(BlsScalar::zero());
                }
            }

            composer.append_custom_gate(constraint);
        }

        Ok(composer)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use super::*;

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
        let result = catch_unwind(|| CompressedCircuit::from_bytes(&encoded));
        assert!(result.is_ok(), "checked decoding must not panic");
        assert!(matches!(
            result.unwrap(),
            Err(Error::InvalidCompressedCircuit)
        ));
    }

    #[test]
    fn valid_indices_are_accepted() {
        assert!(CompressedCircuit::from_bytes(&encode(&circuit())).is_ok());
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
        let setters: [fn(&mut CompressedPolynomial, usize); 11] = [
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
}
