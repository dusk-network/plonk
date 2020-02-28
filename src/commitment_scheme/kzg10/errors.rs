//! Errors related to KZG10

// Represents an error in SRS creation and modification
#[derive(Fail, Debug)]
pub enum SRSError {
    // This error occurs when the user tries to create an SRS and supplies the degree as zero
    #[fail(display = "cannot create an srs with max degree as 0")]
    DegreeIsZero,
    // This error occurs when the user tries to trim an srs down to a degree that is larger than the maximum degree
    #[fail(display = "cannot trim more than the maximum degree")]
    TruncatedDegreeTooLarge,
    // This error occurs when the user tries to trim an srs down to a degree that is zero
    #[fail(display = "cannot trim srs to a maximum size of zero")]
    TruncatedDegreeIsZero,
}
