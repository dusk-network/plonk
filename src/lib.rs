mod commitment_scheme;
pub mod cs;
pub mod srs;
pub mod transcript;
#[macro_use]
extern crate failure;

use new_bls12_381::Scalar;
use std::ops::Add;
use std::ops::Mul;
// While we do not have multiscalar mul in bls12-381; this function will be used as a stub
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
