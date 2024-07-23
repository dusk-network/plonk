// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use hashbrown::HashMap;
use msgpacker::{MsgPacker, Packable, Unpackable};

use alloc::vec::Vec;

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
        let (
            _,
            Self {
                hades_optimization,
                public_inputs,
                witnesses,
                scalars,
                polynomials,
                constraints,
            },
        ) = Self::unpack(&compressed)
            .map_err(|_| Error::InvalidCompressedCircuit)?;

        let scalar_map = scalar_map(hades_optimization);
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
