use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use rand_core::RngCore;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

/// Returns a vector of Scalars of increasing powers of x from x^0 to x^d.
pub(crate) fn powers_of(scalar: &Scalar, max_degree: usize) -> Vec<Scalar> {
    let mut powers = Vec::with_capacity(max_degree + 1);
    powers.push(Scalar::one());
    for i in 1..=max_degree {
        powers.push(powers[i - 1] * scalar);
    }
    powers
}

/// Generates a random Scalar using a RNG seed.
pub(crate) fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    Scalar::from_raw([
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
    ])
}

/// Generates a random G1 Point using an RNG seed.
pub(crate) fn random_g1_point<R: RngCore>(rng: &mut R) -> G1Projective {
    G1Affine::generator() * random_scalar(rng)
}
/// Generates a random G2 point using an RNG seed.
pub(crate) fn random_g2_point<R: RngCore>(rng: &mut R) -> G2Projective {
    G2Affine::generator() * random_scalar(rng)
}

/// This function is only used to generate the SRS.
/// The intention is just to compute the resulting points
/// of the operation `a*P, b*P, c*P ... (n-1)*P` into a `Vec`.
pub(crate) fn slow_multiscalar_mul_single_base(
    scalars: &[Scalar],
    base: G1Projective,
) -> Vec<G1Projective> {
    scalars.par_iter().map(|s| base * *s).collect()
}

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
        *f = tmp * s;
        tmp = new_tmp;
    }
}
#[cfg(test)]
mod test {
    use super::*;
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
}
