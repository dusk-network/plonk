//! Errors related to KZG10

// Represents an error in SRS creation and/or modification
#[derive(Fail, Debug)]
pub enum Error {
    // This error occurs when the user tries to create an SRS and supplies the max degree as zero
    #[fail(display = "cannot create an srs with max degree as 0")]
    DegreeIsZero,
    // This error occurs when the user tries to trim an srs down to a degree that is larger than the maximum degree
    #[fail(display = "cannot trim more than the maximum degree")]
    TruncatedDegreeTooLarge,
    // This error occurs when the user tries to trim an srs down to a degree that is zero
    #[fail(display = "cannot trim srs to a maximum size of zero")]
    TruncatedDegreeIsZero,
    // This error occurs when the user tries to commit to a polynomial whose degree is larger than
    // the supported degree for that proving key
    #[fail(display = "proving key is not large enough to commit to said polynomial")]
    PolynomialDegreeTooLarge,
    // This error occurs when the user tries to commit to a polynomial whose degree is zero
    #[fail(display = "cannot commit to polynomial of zero degree")]
    PolynomialDegreeIsZero,
}
