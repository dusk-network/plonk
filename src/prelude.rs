//! Collection of functions needed to use plonk library.
//!
//! Use this as the only import that you need to interact
//! with the principal data structures of the plonk library.
//!

pub use crate::commitment_scheme::kzg10::{
    key::{CommitKey, OpeningKey},
    PublicParameters,
};
pub use crate::constraint_system::{StandardComposer, Variable};
pub use crate::proof_system::{
    widget::{ProverKey, VerifierKey},
    Proof, Prover, Verifier,
};

/// Re-exported `dusk-bls12_381::Scalar`.
pub use dusk_bls12_381::Scalar as BlsScalar;

/// Re-exported `dusk-jubjub::Scalar`.
pub use dusk_jubjub::Fr as JubJubScalar;

/// Collection of errors that the library exposes/uses.
pub mod plonk_errors {
    pub use crate::commitment_scheme::kzg10::errors::{KZG10Errors, PolyCommitSchemeError};
    pub use crate::constraint_system::cs_errors::{PreProcessingError, ProvingError};
    pub use crate::fft::fft_errors::{FFTError, FFTErrors};
    pub use crate::proof_system::proof_system_errors::{ProofError, ProofErrors};
}
