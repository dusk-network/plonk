use bls12_381::Scalar;
use rayon::prelude::*;

pub fn add_poly_vectors(poly_a: &[Scalar], poly_b: &[Scalar]) -> Vec<Scalar> {
    if poly_a.len() == 0 {
        return poly_b.to_vec();
    }
    if poly_b.len() == 0 {
        return poly_a.to_vec();
    }

    let max_len = std::cmp::max(poly_a.len(), poly_b.len());
    let min_len = std::cmp::min(poly_a.len(), poly_b.len());
    let mut data = Vec::with_capacity(max_len);
    let (mut poly_a_iter, mut poly_b_iter) = (poly_a.iter(), poly_b.iter());

    let partial_addition = poly_a_iter
        .by_ref()
        .zip(poly_b_iter.by_ref())
        .map(|(&a, &b)| a + &b)
        .take(min_len);

    data.extend(partial_addition);
    data.extend(poly_a_iter);
    data.extend(poly_b_iter);

    assert_eq!(data.len(), std::cmp::max(poly_a.len(), poly_b.len()));

    data
}
// Multiplies a polynomial by a scalar
pub fn mul_scalar_poly(scalar: Scalar, poly: &[Scalar]) -> Vec<Scalar> {
    poly.par_iter().map(|coeff| scalar * coeff).collect()
}
