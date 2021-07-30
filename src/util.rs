// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;
use dusk_bls12_381::{
    BlsScalar, G1Affine, G1Projective, G2Affine, G2Projective,
};
use rand_core::{CryptoRng, RngCore};

/// Returns a vector of BlsScalars of increasing powers of x from x^0 to x^d.
pub(crate) fn powers_of(
    scalar: &BlsScalar,
    max_degree: usize,
) -> Vec<BlsScalar> {
    let mut powers = Vec::with_capacity(max_degree + 1);
    powers.push(BlsScalar::one());
    for i in 1..=max_degree {
        powers.push(powers[i - 1] * scalar);
    }
    powers
}

/// Generates a random BlsScalar using a RNG seed.
pub(crate) fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> BlsScalar {
    BlsScalar::random(rng)
}

/// Generates a random G1 Point using an RNG seed.
pub(crate) fn random_g1_point<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G1Projective {
    G1Affine::generator() * random_scalar(rng)
}
/// Generates a random G2 point using an RNG seed.
pub(crate) fn random_g2_point<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G2Projective {
    G2Affine::generator() * random_scalar(rng)
}

/// This function is only used to generate the SRS.
/// The intention is just to compute the resulting points
/// of the operation `a*P, b*P, c*P ... (n-1)*P` into a `Vec`.
pub(crate) fn slow_multiscalar_mul_single_base(
    scalars: &[BlsScalar],
    base: G1Projective,
) -> Vec<G1Projective> {
    scalars.iter().map(|s| base * *s).collect()
}

// while we do not have batch inversion for scalars
use core::ops::MulAssign;

pub fn batch_inversion(v: &mut [BlsScalar]) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2

    // First pass: compute [a, ab, abc, ...]
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = BlsScalar::one();
    for f in v.iter().filter(|f| f != &&BlsScalar::zero()) {
        tmp.mul_assign(f);
        prod.push(tmp);
    }

    // Invert `tmp`.
    tmp = tmp.invert().unwrap(); // Guaranteed to be nonzero.

    // Second pass: iterate backwards to compute inverses
    for (f, s) in v
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|f| f != &&BlsScalar::zero())
        // Backwards, skip last element, fill in one for last term.
        .zip(prod.into_iter().rev().skip(1).chain(Some(BlsScalar::one())))
    {
        // tmp := tmp * f; f := tmp * s = 1/f
        let new_tmp = tmp * *f;
        *f = tmp * s;
        tmp = new_tmp;
    }
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_batch_inversion() {
        let one = BlsScalar::from(1);
        let two = BlsScalar::from(2);
        let three = BlsScalar::from(3);
        let four = BlsScalar::from(4);
        let five = BlsScalar::from(5);

        let original_scalars = vec![one, two, three, four, five];
        let mut inverted_scalars = vec![one, two, three, four, five];

        batch_inversion(&mut inverted_scalars);
        for (x, x_inv) in original_scalars.iter().zip(inverted_scalars.iter()) {
            assert_eq!(x.invert().unwrap(), *x_inv);
        }
    }
}
