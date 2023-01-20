// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::Commitment;
use dusk_bytes::{DeserializableSlice, Serializable};

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

#[cfg(feature = "rkyv-impl")]
impl<C> CheckBytes<C> for ArchivedVerifierKey {
    type Error = StructCheckError;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        check_field(&(*value).n, context, "n")?;
        check_field(&(*value).arithmetic, context, "arithmetic")?;
        check_field(&(*value).logic, context, "logic")?;
        check_field(&(*value).range, context, "range")?;
        check_field(&(*value).fixed_base, context, "fixed_base")?;
        check_field(&(*value).variable_base, context, "variable_base")?;
        check_field(&(*value).permutation, context, "permutation")?;

        Ok(&*value)
    }
}

impl Serializable<{ 20 * Commitment::SIZE + u64::SIZE }> for VerifierKey {
    type Error = dusk_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;
        let mut buff = [0u8; Self::SIZE];
        let mut writer = &mut buff[..];

        writer.write(&(self.n as u64).to_bytes());
        writer.write(&self.arithmetic.q_m.to_bytes());
        writer.write(&self.arithmetic.q_l.to_bytes());
        writer.write(&self.arithmetic.q_r.to_bytes());
        writer.write(&self.arithmetic.q_o.to_bytes());
        writer.write(&self.arithmetic.q_4.to_bytes());
        writer.write(&self.arithmetic.q_c.to_bytes());
        writer.write(&self.arithmetic.q_arith.to_bytes());
        writer.write(&self.logic.q_logic.to_bytes());
        writer.write(&self.range.q_range.to_bytes());
        writer.write(&self.fixed_base.q_fixed_group_add.to_bytes());
        writer.write(&self.variable_base.q_variable_group_add.to_bytes());
        writer.write(&self.permutation.s_sigma_1.to_bytes());
        writer.write(&self.permutation.s_sigma_2.to_bytes());
        writer.write(&self.permutation.s_sigma_3.to_bytes());
        writer.write(&self.permutation.s_sigma_4.to_bytes());

        buff
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<VerifierKey, Self::Error> {
        let mut buffer = &buf[..];

        Ok(Self::from_polynomial_commitments(
            u64::from_reader(&mut buffer)? as usize,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
            Commitment::from_reader(&mut buffer)?,
        ))
    }
}

impl VerifierKey {
    /// Constructs a [`VerifierKey`] from the widget VerifierKey's that are
    /// constructed based on the selector polynomial commitments and the
    /// sigma polynomial commitments.
    pub(crate) fn from_polynomial_commitments(
        n: usize,
        q_m: Commitment,
        q_l: Commitment,
        q_r: Commitment,
        q_o: Commitment,
        q_4: Commitment,
        q_c: Commitment,
        q_arith: Commitment,
        q_logic: Commitment,
        q_range: Commitment,
        q_fixed_group_add: Commitment,
        q_variable_group_add: Commitment,
        s_sigma_1: Commitment,
        s_sigma_2: Commitment,
        s_sigma_3: Commitment,
        s_sigma_4: Commitment,
    ) -> VerifierKey {
        let arithmetic = arithmetic::VerifierKey {
            q_m,
            q_l,
            q_r,
            q_o,
            q_4,
            q_c,
            q_arith,
        };
        let logic = logic::VerifierKey { q_c, q_logic };
        let range = range::VerifierKey { q_range };
        let fixed_base = ecc::scalar_mul::fixed_base::VerifierKey {
            q_l,
            q_r,
            q_fixed_group_add,
        };

        let variable_base = ecc::curve_addition::VerifierKey {
            q_variable_group_add,
        };

        let permutation = permutation::VerifierKey {
            s_sigma_1,
            s_sigma_2,
            s_sigma_3,
            s_sigma_4,
        };

        VerifierKey {
            n,
            arithmetic,
            logic,
            range,
            fixed_base,
            variable_base,
            permutation,
        }
    }
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

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialize_deserialize_verifier_key() {
        use crate::commitment_scheme::Commitment;
        use zero_bls12_381::G1Affine;

        let n = 2usize.pow(5);

        let q_m = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let q_l = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let q_r = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let q_o = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let q_c = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let q_4 = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let q_arith = Commitment(G1Affine::ADDITIVE_GENERATOR);

        let q_range = Commitment(G1Affine::ADDITIVE_GENERATOR);

        let q_fixed_group_add = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let q_variable_group_add = Commitment(G1Affine::ADDITIVE_GENERATOR);

        let q_logic = Commitment(G1Affine::ADDITIVE_GENERATOR);

        let s_sigma_1 = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let s_sigma_2 = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let s_sigma_3 = Commitment(G1Affine::ADDITIVE_GENERATOR);
        let s_sigma_4 = Commitment(G1Affine::ADDITIVE_GENERATOR);

        let arithmetic = arithmetic::VerifierKey {
            q_m,
            q_l,
            q_r,
            q_o,
            q_c,
            q_4,
            q_arith,
        };

        let logic = logic::VerifierKey { q_logic, q_c };

        let range = range::VerifierKey { q_range };

        let fixed_base = ecc::scalar_mul::fixed_base::VerifierKey {
            q_fixed_group_add,
            q_l,
            q_r,
        };
        let variable_base = ecc::curve_addition::VerifierKey {
            q_variable_group_add,
        };

        let permutation = permutation::VerifierKey {
            s_sigma_1,
            s_sigma_2,
            s_sigma_3,
            s_sigma_4,
        };

        let verifier_key = VerifierKey {
            n,
            arithmetic,
            logic,
            range,
            fixed_base,
            variable_base,
            permutation,
        };

        let verifier_key_bytes = verifier_key.to_bytes();
        let got = VerifierKey::from_bytes(&verifier_key_bytes).unwrap();

        assert_eq!(got, verifier_key);
    }
}
