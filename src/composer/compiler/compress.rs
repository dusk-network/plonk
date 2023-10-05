// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use hashbrown::HashMap;
use msgpacker::{MsgPacker, Packable, Unpackable};

use alloc::vec::Vec;

use super::{
    BlsScalar, Builder, Circuit, Compiler, Composer, Constraint, Error,
    Polynomial, Prover, PublicParameters, Selector, Verifier, Witness,
};

mod hades;

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, MsgPacker,
)]
pub struct CompressedConstraint {
    pub polynomial: usize,
    pub w_a: usize,
    pub w_b: usize,
    pub w_d: usize,
    pub w_o: usize,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, MsgPacker,
)]
pub struct CompressedPolynomial {
    pub q_m: usize,
    pub q_l: usize,
    pub q_r: usize,
    pub q_o: usize,
    pub q_c: usize,
    pub q_d: usize,
    pub q_arith: usize,
    pub q_range: usize,
    pub q_logic: usize,
    pub q_fixed_group_add: usize,
    pub q_variable_group_add: usize,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, MsgPacker,
)]
pub enum Version {
    V1,
    V2,
}

impl Version {
    pub fn into_scalars(self) -> HashMap<BlsScalar, usize> {
        match self {
            Version::V1 => {
                [BlsScalar::zero(), BlsScalar::one(), -BlsScalar::one()]
                    .into_iter()
                    .enumerate()
                    .map(|(i, s)| (s, i))
                    .collect()
            }
            Version::V2 => {
                let mut scalars = Self::V1.into_scalars();
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
                scalars
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, MsgPacker)]
pub struct CompressedCircuit {
    version: Version,
    public_inputs: Vec<usize>,
    witnesses: usize,
    scalars: Vec<[u8; BlsScalar::SIZE]>,
    polynomials: Vec<CompressedPolynomial>,
    constraints: Vec<CompressedConstraint>,
}

impl CompressedCircuit {
    pub fn from_circuit<C>(version: Version) -> Result<Vec<u8>, Error>
    where
        C: Circuit,
    {
        let mut builder = Builder::initialized();
        C::default().circuit(&mut builder)?;
        Ok(Self::from_builder(version, builder))
    }

    pub fn from_builder(version: Version, builder: Builder) -> Vec<u8> {
        let mut public_inputs: Vec<_> =
            builder.public_inputs.keys().copied().collect();
        public_inputs.sort();

        let witnesses = builder.witnesses.len();
        let polynomials = builder.constraints;

        let constraints = polynomials.into_iter();
        let mut scalars = version.into_scalars();
        let base_scalars_len = scalars.len();
        let mut polynomials = HashMap::new();
        let constraints = constraints
            .map(
                |Polynomial {
                     q_m,
                     q_l,
                     q_r,
                     q_o,
                     q_c,
                     q_d,
                     q_arith,
                     q_range,
                     q_logic,
                     q_fixed_group_add,
                     q_variable_group_add,
                     w_a,
                     w_b,
                     w_d,
                     w_o,
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
                    let q_c = *scalars.entry(q_c).or_insert(len);
                    let len = scalars.len();
                    let q_d = *scalars.entry(q_d).or_insert(len);
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
                        q_c,
                        q_d,
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
                        w_a: w_a.index(),
                        w_b: w_b.index(),
                        w_d: w_d.index(),
                        w_o: w_o.index(),
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
        // version
        let scalars = scalars.split_off(base_scalars_len);

        let polynomials_map = polynomials;
        let mut polynomials =
            vec![CompressedPolynomial::default(); polynomials_map.len()];
        polynomials_map
            .into_iter()
            .for_each(|(p, i)| polynomials[i] = p);

        let compressed = Self {
            version,
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

    pub fn from_bytes(
        pp: &PublicParameters,
        label: &[u8],
        compressed: &[u8],
    ) -> Result<(Prover, Verifier), Error> {
        let compressed = miniz_oxide::inflate::decompress_to_vec(compressed)
            .map_err(|_| Error::InvalidCompressedCircuit)?;
        let (
            _,
            Self {
                version,
                public_inputs,
                witnesses,
                scalars,
                polynomials,
                constraints,
            },
        ) = Self::unpack(&compressed)
            .map_err(|_| Error::InvalidCompressedCircuit)?;

        let version_scalars_map = version.into_scalars();
        let mut version_scalars =
            vec![BlsScalar::zero(); version_scalars_map.len()];
        version_scalars_map
            .into_iter()
            .for_each(|(s, i)| version_scalars[i] = s);
        for s in scalars {
            version_scalars.push(BlsScalar::from_bytes(&s)?);
        }
        let scalars = version_scalars;

        #[allow(deprecated)]
        // we use `uninitialized` because the decompressor will also contain the
        // dummy constraints, if they were part of the prover when encoding.
        let mut builder = Builder::uninitialized();

        let mut pi = 0;
        (0..witnesses).for_each(|_| {
            builder.append_witness(BlsScalar::zero());
        });

        for (
            i,
            CompressedConstraint {
                polynomial,
                w_a,
                w_b,
                w_d,
                w_o,
            },
        ) in constraints.into_iter().enumerate()
        {
            let CompressedPolynomial {
                q_m,
                q_l,
                q_r,
                q_o,
                q_c,
                q_d,
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
            let q_c = scalars
                .get(q_c)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;
            let q_d = scalars
                .get(q_d)
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

            let w_a = Witness::new(w_a);
            let w_b = Witness::new(w_b);
            let w_d = Witness::new(w_d);
            let w_o = Witness::new(w_o);

            let mut constraint = Constraint::default()
                .set(Selector::Multiplication, q_m)
                .set(Selector::Left, q_l)
                .set(Selector::Right, q_r)
                .set(Selector::Output, q_o)
                .set(Selector::Constant, q_c)
                .set(Selector::Fourth, q_d)
                .set(Selector::Arithmetic, q_arith)
                .set(Selector::Range, q_range)
                .set(Selector::Logic, q_logic)
                .set(Selector::GroupAddFixedBase, q_fixed_group_add)
                .set(Selector::GroupAddVariableBase, q_variable_group_add)
                .a(w_a)
                .b(w_b)
                .d(w_d)
                .o(w_o);

            if let Some(idx) = public_inputs.get(pi) {
                if idx == &i {
                    pi += 1;
                    constraint = constraint.public(BlsScalar::zero());
                }
            }

            builder.append_custom_gate(constraint);
        }

        Compiler::compile_with_builder(pp, label, &builder)
    }
}
