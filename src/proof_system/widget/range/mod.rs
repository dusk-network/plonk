mod proverkey;
mod verifierkey;

pub use proverkey::ProverKey;
pub use verifierkey::VerifierKey;

/// Common functionality across both the ProverKey and VerifierKey are listed below
///
///
///
///
use dusk_bls12_381::Scalar;

// Computes f(f-1)(f-2)(f-3)
fn delta(f: Scalar) -> Scalar {
    let f_1 = f - Scalar::one();
    let f_2 = f - Scalar::from(2);
    let f_3 = f - Scalar::from(3);
    f * f_1 * f_2 * f_3
}
