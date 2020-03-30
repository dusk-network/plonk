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
mod notes {
    #[doc(include = "../docs/notes-composer.md")]
    #[doc(include = "../docs/notes-commitments.md")]
    mod notes_kzg10 {}
    #[doc(include = "../docs/notes-pp.md")]
    mod notes_pa {}
    #[doc(include = "../docs/notes-snark.md")]
    mod notes_prove_verify {}
}
