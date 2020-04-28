//! Errors related to the Constraint system

/* I wanted to encapsulate all of the composer errors on a global one and then define
sub types. But seems quite tricky.
/// Represents an error in the Circuit composing process.
#[derive(Fail, Debug)]
pub enum ComposerError<E>
where
    E: Display + Debug + Sync + Send,
{
    #[fail(display = "Composer error caused by: {:?}", err)]
    ComposerError { err: E },
}
*/

/// Represents an error on the Circuit preprocessing stage.
#[derive(Fail, Debug)]
pub enum PreProcessingError {
    /// This error occurs when the .
    #[fail(display = "the length of the wires it's not the same")]
    MissmatchedPolyLen,
}
