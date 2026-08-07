// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A collection of all possible errors encountered in PLONK.

use core::error::Error as CoreError;
use core::fmt;

use dusk_bytes::Error as DuskBytesError;

/// Defines all possible errors that can be encountered in PLONK.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    // FFT errors
    /// This error occurs when an error triggers on any of the fft module
    /// functions.
    InvalidEvalDomainSize {
        /// Log size of the group
        log_size_of_group: u32,
        /// Two adacity generated
        adacity: u32,
    },

    // Prover/Verifier errors
    /// This error occurs when a proof verification fails.
    ProofVerificationError,
    /// This error occurs when the circuit is not provided with all of the
    /// required inputs.
    CircuitInputsNotFound,
    /// This error occurs when we want to verify a Proof but the pi_constructor
    /// attribute is uninitialized.
    UninitializedPIGenerator,
    /// PublicInput serialization error
    InvalidPublicInputBytes,
    /// This error occurs when the Prover structure already contains a
    /// preprocessed circuit inside, but you call preprocess again.
    CircuitAlreadyPreprocessed,
    /// This error occurs when the circuit description has a different amount
    /// of gates than the circuit for the proof creation.
    /// The order: (description_size, circuit_size)
    InvalidCircuitSize(usize, usize),
    /// This error occurs when proof creation fails because the constraint
    /// system is not satisfied: the witness assignment or the appended
    /// constants do not match the compiled circuit description.
    CircuitUnsatisfied,

    // Preprocessing errors
    /// This error occurs when an error triggers during the preprocessing
    /// stage.
    MismatchedPolyLen,

    // KZG10 errors
    /// This error occurs when the user tries to create PublicParameters
    /// and supplies the max degree as zero.
    DegreeIsZero,
    /// This error occurs when the user tries to trim PublicParameters
    /// to a degree that is larger than the maximum degree.
    TruncatedDegreeTooLarge,
    /// This error occurs when the user tries to trim PublicParameters
    /// down to a degree that is zero.
    TruncatedDegreeIsZero,
    /// This error occurs when the user tries to commit to a polynomial whose
    /// degree is larger than the supported degree for that proving key.
    PolynomialDegreeTooLarge,
    /// This error occurs when the user tries to commit to a polynomial whose
    /// degree is zero.
    PolynomialDegreeIsZero,
    /// This error occurs when the pairing check fails at being equal to the
    /// Identity point.
    PairingCheckFailure,

    // Serialization errors
    /// Dusk-bytes serialization error
    BytesError(DuskBytesError),
    /// This error occurs when there are not enough bytes to read out of a
    /// slice during deserialization.
    NotEnoughBytes,
    /// This error occurs when a malformed point is decoded from a byte array.
    PointMalformed,
    /// This error occurs when a malformed BLS scalar is decoded from a byte
    /// array.
    BlsScalarMalformed,
    /// This error occurs when a malformed JubJub scalar is decoded from a byte
    /// array.
    JubJubScalarMalformed,
    /// This error occurs when a fixed-base generator is not a prime-order
    /// Jubjub point.
    JubJubGeneratorNotPrimeOrder,
    /// This error occurs when a JubJub point appended to a circuit as a
    /// constant is not an on-curve member of the prime-order subgroup in a
    /// consistent extended representation.
    JubJubPointNotTorsionFree,
    /// This error occurs when a JubJub point in extended coordinates has a
    /// zero `Z` coordinate, denoting no affine point, and so cannot be
    /// appended to a circuit or compared against.
    JubJubPointDegenerate,
    /// WNAF2k should be in `[-1, 0, 1]`
    UnsupportedWNAF2k,
    /// The provided public inputs doesn't match the circuit definition
    PublicInputNotFound {
        /// Expected public input wasn't found
        index: usize,
    },
    /// The provided public inputs length doesn't match the processed verifier
    InconsistentPublicInputsLen {
        /// Expected value
        expected: usize,
        /// Provided value
        provided: usize,
    },
    /// The provided compressed circuit bytes representation is invalid.
    InvalidCompressedCircuit,
    /// Legacy proving was requested but this build disables legacy proving.
    LegacyProvingDisabled,
    /// The requested proving version is no longer supported.
    UnsupportedProvingVersion,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvalDomainSize {
                log_size_of_group,
                adacity,
            } => write!(
                f,
                "Log-size of the EvaluationDomain group > TWO_ADACITY\
            Size: {:?} > TWO_ADACITY = {:?}",
                log_size_of_group, adacity
            ),
            Self::ProofVerificationError => {
                write!(f, "proof verification failed")
            }
            Self::CircuitInputsNotFound => {
                write!(f, "circuit inputs not found")
            }
            Self::UninitializedPIGenerator => {
                write!(f, "PI generator uninitialized")
            }
            Self::InvalidPublicInputBytes => {
                write!(f, "invalid public input bytes")
            }
            Self::MismatchedPolyLen => {
                write!(f, "the length of the wires is not the same")
            }
            Self::CircuitAlreadyPreprocessed => {
                write!(f, "circuit has already been preprocessed")
            }
            Self::InvalidCircuitSize(description_size, circuit_size) => {
                write!(
                    f,
                    "circuit description has a different amount of gates than the circuit for the proof creation: description size = {description_size}, circuit size = {circuit_size}"
                )
            }
            Self::CircuitUnsatisfied => write!(
                f,
                "the circuit is not satisfied: the witness assignment or the \
                 appended constants do not match the compiled circuit \
                 description"
            ),
            Self::DegreeIsZero => {
                write!(f, "cannot create PublicParameters with max degree 0")
            }
            Self::TruncatedDegreeTooLarge => {
                write!(f, "cannot trim more than the maximum degree")
            }
            Self::TruncatedDegreeIsZero => write!(
                f,
                "cannot trim PublicParameters to a maximum size of zero"
            ),
            Self::PolynomialDegreeTooLarge => write!(
                f,
                "proving key is not large enough to commit to said polynomial"
            ),
            Self::PolynomialDegreeIsZero => {
                write!(f, "cannot commit to polynomial of zero degree")
            }
            Self::PairingCheckFailure => write!(f, "pairing check failed"),
            Self::NotEnoughBytes => write!(f, "not enough bytes left to read"),
            Self::PointMalformed => write!(f, "BLS point bytes malformed"),
            Self::BlsScalarMalformed => write!(f, "BLS scalar bytes malformed"),
            Self::JubJubScalarMalformed => {
                write!(f, "JubJub scalar bytes malformed")
            }
            Self::JubJubGeneratorNotPrimeOrder => {
                write!(f, "JubJub generator is not a prime-order point")
            }
            Self::JubJubPointNotTorsionFree => {
                write!(f, "JubJub point is not in the prime-order subgroup")
            }
            Self::JubJubPointDegenerate => write!(
                f,
                "JubJub point has a zero Z coordinate and denotes no affine point"
            ),
            Self::BytesError(err) => write!(f, "{:?}", err),
            Self::UnsupportedWNAF2k => write!(
                f,
                "WNAF2k cannot hold values not contained in `[-1..1]`"
            ),
            Self::PublicInputNotFound { index } => write!(
                f,
                "The public input of index {} is defined in the circuit description, but wasn't declared in the prove instance",
                index
            ),
            Self::InconsistentPublicInputsLen { expected, provided } => write!(
                f,
                "The provided public inputs set of length {} doesn't match the processed verifier: {}",
                provided, expected
            ),
            Self::InvalidCompressedCircuit => {
                write!(f, "invalid compressed circuit")
            }
            Self::LegacyProvingDisabled => {
                write!(f, "legacy proving is disabled in this build")
            }
            Self::UnsupportedProvingVersion => {
                write!(f, "requested proving version is unsupported")
            }
        }
    }
}

impl From<DuskBytesError> for Error {
    fn from(bytes_err: DuskBytesError) -> Self {
        Self::BytesError(bytes_err)
    }
}

impl CoreError for Error {}

// The `Display` and `CoreError` impls above are unconditional; this module is
// gated on `alloc` only because it renders through `to_string`.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use alloc::string::ToString;

    use dusk_bls12_381::BlsScalar;
    use dusk_bytes::{DeserializableSlice, Serializable};

    use super::*;

    #[test]
    fn display_arms_are_exercised() {
        let bogus = [0u8; BlsScalar::SIZE - 1];
        let dusk_err = BlsScalar::from_slice(&bogus)
            .expect_err("decoding from a short slice must fail");
        let bytes_error: Error = dusk_err.into();
        assert!(matches!(bytes_error, Error::BytesError(_)));

        // Format each variant at least once so the `Display` impl gets covered.
        let all_errors: [Error; 26] = [
            Error::InvalidEvalDomainSize {
                log_size_of_group: 32,
                adacity: 28,
            },
            Error::ProofVerificationError,
            Error::CircuitInputsNotFound,
            Error::UninitializedPIGenerator,
            Error::InvalidPublicInputBytes,
            Error::CircuitAlreadyPreprocessed,
            Error::InvalidCircuitSize(1, 2),
            Error::CircuitUnsatisfied,
            Error::MismatchedPolyLen,
            Error::DegreeIsZero,
            Error::TruncatedDegreeTooLarge,
            Error::TruncatedDegreeIsZero,
            Error::PolynomialDegreeTooLarge,
            Error::PolynomialDegreeIsZero,
            Error::PairingCheckFailure,
            Error::NotEnoughBytes,
            Error::PointMalformed,
            Error::BlsScalarMalformed,
            Error::JubJubScalarMalformed,
            Error::JubJubGeneratorNotPrimeOrder,
            Error::JubJubPointNotTorsionFree,
            Error::JubJubPointDegenerate,
            Error::UnsupportedWNAF2k,
            Error::InvalidCompressedCircuit,
            Error::LegacyProvingDisabled,
            Error::UnsupportedProvingVersion,
        ];

        for e in all_errors {
            let s = e.to_string();
            assert!(!s.is_empty());
        }

        // Variants with payloads.
        assert!(
            Error::PublicInputNotFound { index: 7 }
                .to_string()
                .contains("index")
        );
        assert!(
            Error::InconsistentPublicInputsLen {
                expected: 1,
                provided: 2
            }
            .to_string()
            .contains("provided")
        );

        assert!(!bytes_error.to_string().is_empty());

        let _as_core_error: &dyn CoreError = &Error::ProofVerificationError;
        // Since Rust 1.81 `std::error::Error` is a re-export of
        // `core::error::Error`, so the `core` impl is what a `std` consumer
        // sees. This coercion fails to compile if that ever stops holding.
        #[cfg(feature = "std")]
        let _as_std_error: &dyn std::error::Error =
            &Error::ProofVerificationError;
    }
}
