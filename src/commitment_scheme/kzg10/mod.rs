use new_bls12_381::{G1Affine, G2Affine, G2Prepared, Scalar};
// Code was taken and modified from Pratyush: https://github.com/scipr-lab/poly-commit/blob/master/src/kzg10/mod.rs
pub mod errors;
mod key;
mod srs;

pub struct Proof {
    /// This is a commitment to the witness polynomial; see [KZG10] for more details.
    pub w: G1Affine,
    /// This is the evaluation of the random polynomial at the point for which
    /// the evaluation proof was produced.
    pub random_v: Scalar,
}
