use new_bls12_381::{G1Affine, G1Projective, Scalar};
use rand_core::RngCore;
// Code was taken and modified from Pratyush: https://github.com/scipr-lab/poly-commit/blob/master/src/kzg10/mod.rs
pub mod errors;
pub mod key;
pub mod srs;

pub use key::{ProverKey, VerifierKey};

pub struct Proof {
    /// This is a commitment to the witness polynomial; see [KZG10] for more details.
    pub w: G1Affine,
    /// This is the evaluation of the random polynomial at the point for which
    /// the evaluation proof was produced.
    pub random_v: Scalar,
}
#[derive(Copy, Clone, Debug)]
pub struct Commitment(
    /// The commitment is a group element.
    pub G1Affine,
);

impl Commitment {
    pub fn from_projective(g: G1Projective) -> Self {
        Self(g.into())
    }
    pub fn from_affine(g: G1Affine) -> Self {
        Self(g)
    }

    pub fn empty() -> Self {
        Commitment(G1Affine::identity())
    }
}

/// Blinding Polynomial is a random polynomial
/// Which will be used to blind the original
/// polynomial that we are committing to
pub struct BlindingPolynomial(Vec<Scalar>);

impl BlindingPolynomial {
    // Initialise the zero polynomial
    fn empty() -> Self {
        BlindingPolynomial(vec![Scalar::zero(); 1])
    }
    /// Computes a random blinding polynomial
    pub fn rand<R: RngCore>(hiding_degree: usize, mut rng: &mut R) -> Self {
        // A polynomial with degree n has n+1 terms
        let num_of_coeffs = hiding_degree + 1;
        let rand_coeffs = compute_n_random_scalars(num_of_coeffs, &mut rng);
        BlindingPolynomial(rand_coeffs)
    }
}

fn compute_n_random_scalars<R: RngCore>(n: usize, rng: &mut R) -> Vec<Scalar> {
    let mut vec = Vec::with_capacity(n);
    for _ in 0..n {
        vec.push(Scalar::from_raw([
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ]))
    }
    vec
}
