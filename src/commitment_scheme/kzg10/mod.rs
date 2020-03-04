//! The KZG10 commitment scheme is used to facilitate
//! interations between the prover and verifier.
use bls12_381::{G1Affine, G1Projective, Scalar};
// Code was taken and modified from Pratyush: https://github.com/scipr-lab/poly-commit/blob/master/src/kzg10/mod.rs
pub mod errors;
pub mod key;
pub mod srs;

pub use key::{ProverKey, VerifierKey};
pub use srs::SRS;
pub struct Proof {
    /// This is a commitment to the witness polynomial see [KZG10] for more details.
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
