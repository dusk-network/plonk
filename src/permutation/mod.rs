//! The permutation module contains the construction of
//! shifted wire indices, with added random factors,
//! which are evaluated as vectors.
//!
//! The evaluation of the permutation polynomial is performed as compound evaluation,
//! from the succesive roots of unity. Until the final evaluation, where
//! z(x) will be equal to the total product of all the permutation terms,
//! except for the last one.
//!
//! Checking that z(x) at the first root of unity is equal to one,
//! ensure that the grand product is also equal to one. This is because the
//! 'rotation' given by this polynomial cycles back to the start.
//!
//! Beta and Gamma are used as to ensure that although the evaluated
//! final products are the same, their Identity and Copy polynomials
//! are non mailicious.

pub(crate) mod constants;
pub(crate) mod grand_product_lineariser;
pub(crate) mod grand_product_quotient;
pub mod permutation;
pub use permutation::Permutation;
