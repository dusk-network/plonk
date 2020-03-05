//! This module contains the encoding for the
//! KZG10 polynomial commitment scheme.
//!
//! The KZG10 commitment scheme is a homomorphic commitment scheme introduced
//! by Kate, Zaverucha and Goldberg.
//!
///A polynomial commitment scheme allows the committer to commit to a polynomial
/// with a short string. The commitment of a polynomial returns values, based on
/// the input, in terms of evaluations of `some` input. This verifier, who recieves
/// this evaluation, checks the claims made by the at these values.
///
/// Ideally we should cleanly abstract away the polynomial commitment scheme
/// We note that PLONK makes use of the linearisation technique  
/// conceived in SONIC [Mary Maller]. This technique implicitly requires the
/// commitment scheme to be homomorphic. `Merkle Tree like` techniques such as FRI are not homomorphic
/// and therefore for PLONK to be usable with all commitment schemes without modification, one would need to remove the lineariser
/// XXX: This empty trait is left here so that Rust docs does not complain that we are documenting nothing. It is also a reminder that we ideally should find a good abstraction
trait CommitmentScheme {
    type Proof;
}

pub mod kzg10;
