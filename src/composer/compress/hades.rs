// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use sha2::{Digest, Sha512};

use super::BlsScalar;

const CONSTANTS: usize = 960;

// Extracted from
// https://github.com/dusk-network/Hades252/blob/a4d55e06ee9ff7f549043582e8d194eb0a01bf24/assets/HOWTO.md

pub fn constants() -> [BlsScalar; CONSTANTS] {
    let mut cnst = [BlsScalar::zero(); CONSTANTS];
    let mut p = BlsScalar::one();
    let mut bytes = b"poseidon-for-plonk".to_vec();

    cnst.iter_mut().for_each(|c| {
        bytes = Sha512::digest(bytes.as_slice()).to_vec();

        let mut v = [0x00u8; 64];
        v.copy_from_slice(&bytes[0..64]);

        *c = BlsScalar::from_bytes_wide(&v) + p;
        p = *c;
    });

    cnst
}

const WIDTH: usize = 5;

pub fn mds() -> [[BlsScalar; WIDTH]; WIDTH] {
    let mut matrix = [[BlsScalar::zero(); WIDTH]; WIDTH];
    let mut xs = [BlsScalar::zero(); WIDTH];
    let mut ys = [BlsScalar::zero(); WIDTH];

    // Generate x and y values deterministically for the cauchy matrix
    // where x[i] != y[i] to allow the values to be inverted
    // and there are no duplicates in the x vector or y vector, so that the
    // determinant is always non-zero [a b]
    // [c d]
    // det(M) = (ad - bc) ; if a == b and c == d => det(M) =0
    // For an MDS matrix, every possible mxm submatrix, must have det(M) != 0
    (0..WIDTH).for_each(|i| {
        xs[i] = BlsScalar::from(i as u64);
        ys[i] = BlsScalar::from((i + WIDTH) as u64);
    });

    let mut m = 0;
    (0..WIDTH).for_each(|i| {
        (0..WIDTH).for_each(|j| {
            matrix[m][j] = (xs[i] + ys[j]).invert().unwrap();
        });
        m += 1;
    });

    matrix
}
