/// Ideally we should cleanly abstract away the polynomial commitment scheme
/// We note that PLONK makes use of the linearisation technique  
/// conceived in SONIC [Mary Maller]. This technique implicitly requires the
/// commitment scheme to be homomorphic. `Merkle Tree like` techniques such as FRI are not homomorphic
/// and therefore for PLONK to be usable with all commitment schemes without modification, one would need to remove the lineariser
/// XXX: This empty trait is left here so that Rust docs does not complain that we are documenting nothing. It is also a reminder that we ideally should find a good abstraction
trait CommitmentScheme {
    type Proof;
}

/// N.B. KZG10 has two variations polycommit_DL and polycommit_PED
/// PLONK uses polycommit_DL in the paper and blinds the polynomials directly
/// However, doing it this way significantly increases the size of FFTs that are needed.
/// This implementation will first use polycommit_DL, however we will allow users to switch to polycommit_PED
/// This would increase the proof size by 3 elements and would require the a larger SRS in the ceremony
/// XXX: In general, unless we can find a more economical way in regards to FFTs, it may be better to blind in the commitment scheme
/// We note that the main FFT cost of 8n arise due to the blinded grand product polynomial component in the quotient polynomial
pub mod kzg10;
