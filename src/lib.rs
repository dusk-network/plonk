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
pub mod notes {
    #[doc(include = "../docs/notes-lp.md")]
    pub mod notes_interpolation {}
    #[doc(include = "../docs/notes-commitments.md")]
    pub mod notes_kzg10 {}
    #[doc(include = "../docs/notes-pp.md")]
    pub mod notes_pa {}
    #[doc(include = "../docs/notes-snark.md")]
    pub mod notes_prove_verify {}

}
