#![feature(external_doc)]
pub mod commitment_scheme;
pub mod constraint_system;
pub mod fft;
mod permutation;
pub mod transcript;
mod util;

#[macro_use]
extern crate failure;

#[doc(include = "../docs/notes-intro.md")]
pub mod notes {
    #[doc(include = "../docs/notes-composer.md")]
    pub mod circuit_composer {}
    #[doc(include = "../docs/notes-commitments.md")]
    pub mod commitment_schemes {}
    #[doc(include = "../docs/notes-pa.md")]
    pub mod permutation_arguments {}
    #[doc(include = "../docs/notes-snark.md")]
    pub mod snark_construction {}
}
