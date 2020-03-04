use bls12_381::Scalar;
use std::ops::{Add, Mul};

/// Computes 1,v, v^2, v^3,..v^max_degree
pub fn powers_of(scalar: &Scalar, max_degree: usize) -> Vec<Scalar> {
    let mut powers = Vec::with_capacity(max_degree + 1);
    powers.push(Scalar::one());
    for i in 1..=max_degree {
        powers.push(powers[i - 1] * scalar);
    }
    powers
}

/// While we do not have multiscalar mul in bls12-381; this function will be used as a stub
pub(crate) fn multiscalar_mul<K, T: Mul<Scalar, Output = K> + Copy>(
    scalars: &Vec<Scalar>,
    bases: &Vec<T>,
) -> Vec<K> {
    scalars
        .iter()
        .zip(bases.iter())
        .map(|(s, b)| *b * *s)
        .collect()
}

pub(crate) fn multiscalar_mul_single_base<K, T: Mul<Scalar, Output = K> + Copy>(
    scalars: &Vec<Scalar>,
    base: T,
) -> Vec<K> {
    scalars.iter().map(|s| base * *s).collect()
}
pub(crate) fn sum_points<T: Add<T, Output = T> + Copy>(points: &Vec<T>) -> T {
    let mut sum = points[0];
    for i in 1..points.len() {
        sum = sum + points[i]
    }
    sum
}
// Taken from zexe library
// while we do not have batch inversion for scalars
use std::ops::MulAssign;
pub fn batch_inversion(v: &mut [Scalar]) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2

    // First pass: compute [a, ab, abc, ...]
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = Scalar::one();
    for f in v.iter().filter(|f| !(f == &&Scalar::zero())) {
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
        .filter(|f| !(f == &&Scalar::zero()))
        // Backwards, skip last element, fill in one for last term.
        .zip(prod.into_iter().rev().skip(1).chain(Some(Scalar::one())))
    {
        // tmp := tmp * f; f := tmp * s = 1/f
        let new_tmp = tmp * *f;
        *f = tmp * &s;
        tmp = new_tmp;
    }
}

#[test]
fn test_batch_inversion() {
    let one = Scalar::from(1);
    let two = Scalar::from(2);
    let three = Scalar::from(3);
    let four = Scalar::from(4);
    let five = Scalar::from(5);

    let original_scalars = vec![one, two, three, four, five];
    let mut inverted_scalars = vec![one, two, three, four, five];

    batch_inversion(&mut inverted_scalars);
    for (x, x_inv) in original_scalars.iter().zip(inverted_scalars.iter()) {
        assert_eq!(x.invert().unwrap(), *x_inv);
    }
}
