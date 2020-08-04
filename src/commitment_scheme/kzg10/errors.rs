//! Errors related to KZG10

use thiserror::Error;

/// Represents an error in the PublicParameters creation and or modification.
#[derive(Error, Debug)]
pub enum KZG10Errors {
    /// This error occurs when the user tries to create PublicParameters
    /// and supplies the max degree as zero.
    #[error("cannot create PublicParameters with max degree as 0")]
    DegreeIsZero,
    /// This error occurs when the user tries to trim PublicParameters
    /// to a degree that is larger than the maximum degree.
    #[error("cannot trim more than the maximum degree")]
    TruncatedDegreeTooLarge,
    /// This error occurs when the user tries to trim PublicParameters
    /// down to a degree that is zero.
    #[error("cannot trim PublicParameters to a maximum size of zero")]
    TruncatedDegreeIsZero,
    /// This error occurs when the user tries to commit to a polynomial whose degree is larger than
    /// the supported degree for that proving key.
    #[error("proving key is not large enough to commit to said polynomial")]
    PolynomialDegreeTooLarge,
    /// This error occurs when the user tries to commit to a polynomial whose degree is zero.
    #[error("cannot commit to polynomial of zero degree")]
    PolynomialDegreeIsZero,
    /// This error occurs when the pairing check fails at being equal to the Identity point.
    #[error("pairing check failed")]
    PairingCheckFailure,
}
