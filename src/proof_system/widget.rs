// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

pub mod arithmetic;
pub mod ecc;
pub mod logic;
pub mod permutation;
pub mod range;

/// PLONK circuit Verification Key.
///
/// This structure is used by the Verifier in order to verify a
/// [`Proof`](super::Proof).
#[derive(Debug, PartialEq, Eq, Copy, Clone)]

pub struct VerifierKey {
    /// Circuit size (not padded to a power of two).
    pub(crate) n: usize,
    /// VerifierKey for arithmetic gates
    pub(crate) arithmetic: arithmetic::VerifierKey,
    /// VerifierKey for logic gates
    pub(crate) logic: logic::VerifierKey,
    /// VerifierKey for range gates
    pub(crate) range: range::VerifierKey,
    /// VerifierKey for fixed base curve addition gates
    pub(crate) fixed_base: ecc::scalar_mul::fixed_base::VerifierKey,
    /// VerifierKey for variable base curve addition gates
    pub(crate) variable_base: ecc::curve_addition::VerifierKey,
    /// VerifierKey for permutation checks
    pub(crate) permutation: permutation::VerifierKey,
}

use crate::{fft::Evaluations, transcript::TranscriptProtocol};
use merlin::Transcript;

impl VerifierKey {
    /// Adds the circuit description to the transcript
    pub(crate) fn seed_transcript(&self, transcript: &mut Transcript) {
        transcript.append_commitment(b"q_m", &self.arithmetic.q_m);
        transcript.append_commitment(b"q_l", &self.arithmetic.q_l);
        transcript.append_commitment(b"q_r", &self.arithmetic.q_r);
        transcript.append_commitment(b"q_o", &self.arithmetic.q_o);
        transcript.append_commitment(b"q_c", &self.arithmetic.q_c);
        transcript.append_commitment(b"q_4", &self.arithmetic.q_4);
        transcript.append_commitment(b"q_arith", &self.arithmetic.q_arith);
        transcript.append_commitment(b"q_range", &self.range.q_range);
        transcript.append_commitment(b"q_logic", &self.logic.q_logic);
        transcript.append_commitment(
            b"q_variable_group_add",
            &self.variable_base.q_variable_group_add,
        );
        transcript.append_commitment(
            b"q_fixed_group_add",
            &self.fixed_base.q_fixed_group_add,
        );

        transcript.append_commitment(b"s_sigma_1", &self.permutation.s_sigma_1);
        transcript.append_commitment(b"s_sigma_2", &self.permutation.s_sigma_2);
        transcript.append_commitment(b"s_sigma_3", &self.permutation.s_sigma_3);
        transcript.append_commitment(b"s_sigma_4", &self.permutation.s_sigma_1);

        // Append circuit size to transcript
        transcript.circuit_domain_sep(self.n as u64);
    }
}

/// PLONK circuit Proving Key.
///
/// This structure is used by the Prover in order to construct a
/// [`Proof`](crate::proof_system::Proof).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProverKey {
    /// Circuit size
    pub(crate) n: usize,
    /// ProverKey for arithmetic gate
    pub(crate) arithmetic: arithmetic::ProverKey,
    /// ProverKey for logic gate
    pub(crate) logic: logic::ProverKey,
    /// ProverKey for range gate
    pub(crate) range: range::ProverKey,
    /// ProverKey for fixed base curve addition gates
    pub(crate) fixed_base: ecc::scalar_mul::fixed_base::ProverKey,
    /// ProverKey for variable base curve addition gates
    pub(crate) variable_base: ecc::curve_addition::ProverKey,
    /// ProverKey for permutation checks
    pub(crate) permutation: permutation::ProverKey,
    // Pre-processes the 8n Evaluations for the vanishing polynomial, so
    // they do not need to be computed at the proving stage.
    // Note: With this, we can combine all parts of the quotient polynomial
    // in their evaluation phase and divide by the quotient
    // polynomial without having to perform IFFT
    pub(crate) v_h_coset_8n: Evaluations,
}

impl ProverKey {
    pub(crate) fn v_h_coset_8n(&self) -> &Evaluations {
        &self.v_h_coset_8n
    }
}
