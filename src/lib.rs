#![feature(external_doc)]
pub mod commitment_scheme;
pub mod constraint_system;
pub mod fft;
mod permutation;
pub mod transcript;
mod util;

#[macro_use]
extern crate failure;

#[doc(include = "../docs/introduction.md")]
mod notes {
    #[doc(include = "../docs/notes-lp.md")]
    mod notes_interpolation {}
    #[doc(include = "../docs/notes-commitments.md")]
    mod notes_KZG10 {}
    #[doc(include = "../docs/notes-pp.md")]
    mod notes_pa {}
    #[doc(include = "../docs/notes-snark.md")]
    mod notes_prove_verify {}
}