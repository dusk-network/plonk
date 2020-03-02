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
