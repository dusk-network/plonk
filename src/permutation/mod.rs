//! The permutation module contains the construction of
//! shifted wire indices, with added random factors,
//! which are evaluated as vectors.

pub(crate) mod constants;
pub(crate) mod grand_product_lineariser;
pub(crate) mod grand_product_quotient;
pub mod permutation;
pub use permutation::Permutation;
