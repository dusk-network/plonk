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

#[cfg(feature = "rkyv-impl")]
use crate::util::check_field;
#[cfg(feature = "rkyv-impl")]
use bytecheck::{CheckBytes, StructCheckError};
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

/// PLONK circuit Verification Key.
///
/// This structure is used by the Verifier in order to verify a
/// [`Proof`](super::Proof).
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace"))
)]
pub struct VerifierKey {
    /// Circuit size (not padded to a power of two).
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) n: usize,
    /// VerifierKey for arithmetic gates
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) arithmetic: arithmetic::VerifierKey,
    /// VerifierKey for logic gates
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) logic: logic::VerifierKey,
    /// VerifierKey for range gates
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) range: range::VerifierKey,
    /// VerifierKey for fixed base curve addition gates
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) fixed_base: ecc::scalar_mul::fixed_base::VerifierKey,
    /// VerifierKey for variable base curve addition gates
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) variable_base: ecc::curve_addition::VerifierKey,
    /// VerifierKey for permutation checks
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
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

#[cfg(feature = "alloc")]
pub(crate) mod alloc {
    use super::*;
    use crate::{
        error::Error,
        fft::{EvaluationDomain, Evaluations, Polynomial},
        transcript::TranscriptProtocol,
    };
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use merlin::Transcript;
    use zero_bls12_381::Fr as BlsScalar;

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

            transcript
                .append_commitment(b"s_sigma_1", &self.permutation.s_sigma_1);
            transcript
                .append_commitment(b"s_sigma_2", &self.permutation.s_sigma_2);
            transcript
                .append_commitment(b"s_sigma_3", &self.permutation.s_sigma_3);
            transcript
                .append_commitment(b"s_sigma_4", &self.permutation.s_sigma_1);

            // Append circuit size to transcript
            transcript.circuit_domain_sep(self.n as u64);
        }
    }

    /// PLONK circuit Proving Key.
    ///
    /// This structure is used by the Prover in order to construct a
    /// [`Proof`](crate::proof_system::Proof).
    #[derive(Debug, PartialEq, Eq, Clone)]
    #[cfg_attr(
        feature = "rkyv-impl",
        derive(Archive, Deserialize, Serialize),
        archive(bound(serialize = "__S: Serializer + ScratchSpace")),
        archive_attr(derive(CheckBytes))
    )]
    pub struct ProverKey {
        /// Circuit size
        #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
        pub(crate) n: usize,
        /// ProverKey for arithmetic gate
        #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
        pub(crate) arithmetic: arithmetic::ProverKey,
        /// ProverKey for logic gate
        #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
        pub(crate) logic: logic::ProverKey,
        /// ProverKey for range gate
        #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
        pub(crate) range: range::ProverKey,
        /// ProverKey for fixed base curve addition gates
        #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
        pub(crate) fixed_base: ecc::scalar_mul::fixed_base::ProverKey,
        /// ProverKey for variable base curve addition gates
        #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
        pub(crate) variable_base: ecc::curve_addition::ProverKey,
        /// ProverKey for permutation checks
        #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
        pub(crate) permutation: permutation::ProverKey,
        // Pre-processes the 8n Evaluations for the vanishing polynomial, so
        // they do not need to be computed at the proving stage.
        // Note: With this, we can combine all parts of the quotient polynomial
        // in their evaluation phase and divide by the quotient
        // polynomial without having to perform IFFT
        #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
        pub(crate) v_h_coset_8n: Evaluations,
    }

    impl ProverKey {
        /// Returns the size of the ProverKey for serialization.
        ///
        /// Note:
        /// Duplicate polynomials of the ProverKey (e.g. `q_l`, `q_r` and `q_c`)
        /// are only counted once.
        fn serialization_size(&self) -> usize {
            // Fetch size in bytes of each Polynomial
            let poly_size = self.arithmetic.q_m.0.len() * BlsScalar::SIZE;
            // Fetch size in bytes of each Evaluations
            let eval_size = self.arithmetic.q_m.1.evals.len() * BlsScalar::SIZE
                + EvaluationDomain::SIZE;

            // The amount of distinct polynomials in `ProverKey`
            // 7 (arithmetic) + 1 (logic) + 1 (range) + 1 (fixed_base)
            // + 1 (variable_base) + 4 (permutation)
            let poly_num = 15;

            // The amount of distinct evaluations in `ProverKey`
            // 20 (poly_num) + 1 (permutation) + 1 (v_h_coset_4n)
            let eval_num = 22;

            // The amount of i64 in `ProverKey`
            // 1 (self.n) + 1 (eval_size) + 20 (poly_num)
            let i64_num = 22;

            // Calculate the amount of bytes needed to serialize `ProverKey`
            poly_size * poly_num + eval_size * eval_num + u64::SIZE * i64_num
        }

        /// Serializes a [`ProverKey`] struct into a Vec of bytes.
        #[allow(unused_must_use)]
        pub fn to_var_bytes(&self) -> Vec<u8> {
            use dusk_bytes::Write;
            let size = self.serialization_size();
            let eval_size = self.arithmetic.q_m.1.evals.len() * BlsScalar::SIZE
                + EvaluationDomain::SIZE;

            let mut bytes = vec![0u8; size];

            let mut writer = &mut bytes[..];
            writer.write(&(self.n as u64).to_bytes());
            // Write Evaluation len in bytes.
            writer.write(&(eval_size as u64).to_bytes());

            // Arithmetic
            writer.write(&(self.arithmetic.q_m.0.len() as u64).to_bytes());
            writer.write(&self.arithmetic.q_m.0.to_var_bytes());
            writer.write(&self.arithmetic.q_m.1.to_var_bytes());

            writer.write(&(self.arithmetic.q_l.0.len() as u64).to_bytes());
            writer.write(&self.arithmetic.q_l.0.to_var_bytes());
            writer.write(&self.arithmetic.q_l.1.to_var_bytes());

            writer.write(&(self.arithmetic.q_r.0.len() as u64).to_bytes());
            writer.write(&self.arithmetic.q_r.0.to_var_bytes());
            writer.write(&self.arithmetic.q_r.1.to_var_bytes());

            writer.write(&(self.arithmetic.q_o.0.len() as u64).to_bytes());
            writer.write(&self.arithmetic.q_o.0.to_var_bytes());
            writer.write(&self.arithmetic.q_o.1.to_var_bytes());

            writer.write(&(self.arithmetic.q_4.0.len() as u64).to_bytes());
            writer.write(&self.arithmetic.q_4.0.to_var_bytes());
            writer.write(&self.arithmetic.q_4.1.to_var_bytes());

            writer.write(&(self.arithmetic.q_c.0.len() as u64).to_bytes());
            writer.write(&self.arithmetic.q_c.0.to_var_bytes());
            writer.write(&self.arithmetic.q_c.1.to_var_bytes());

            writer.write(&(self.arithmetic.q_arith.0.len() as u64).to_bytes());
            writer.write(&self.arithmetic.q_arith.0.to_var_bytes());
            writer.write(&self.arithmetic.q_arith.1.to_var_bytes());

            // Logic
            writer.write(&(self.logic.q_logic.0.len() as u64).to_bytes());
            writer.write(&self.logic.q_logic.0.to_var_bytes());
            writer.write(&self.logic.q_logic.1.to_var_bytes());

            // Range
            writer.write(&(self.range.q_range.0.len() as u64).to_bytes());
            writer.write(&self.range.q_range.0.to_var_bytes());
            writer.write(&self.range.q_range.1.to_var_bytes());

            // Fixed base multiplication
            writer.write(
                &(self.fixed_base.q_fixed_group_add.0.len() as u64).to_bytes(),
            );
            writer.write(&self.fixed_base.q_fixed_group_add.0.to_var_bytes());
            writer.write(&self.fixed_base.q_fixed_group_add.1.to_var_bytes());

            // Witness base addition
            writer.write(
                &(self.variable_base.q_variable_group_add.0.len() as u64)
                    .to_bytes(),
            );
            writer.write(
                &self.variable_base.q_variable_group_add.0.to_var_bytes(),
            );
            writer.write(
                &self.variable_base.q_variable_group_add.1.to_var_bytes(),
            );

            // Permutation
            writer
                .write(&(self.permutation.s_sigma_1.0.len() as u64).to_bytes());
            writer.write(&self.permutation.s_sigma_1.0.to_var_bytes());
            writer.write(&self.permutation.s_sigma_1.1.to_var_bytes());

            writer
                .write(&(self.permutation.s_sigma_2.0.len() as u64).to_bytes());
            writer.write(&self.permutation.s_sigma_2.0.to_var_bytes());
            writer.write(&self.permutation.s_sigma_2.1.to_var_bytes());

            writer
                .write(&(self.permutation.s_sigma_3.0.len() as u64).to_bytes());
            writer.write(&self.permutation.s_sigma_3.0.to_var_bytes());
            writer.write(&self.permutation.s_sigma_3.1.to_var_bytes());

            writer
                .write(&(self.permutation.s_sigma_4.0.len() as u64).to_bytes());
            writer.write(&self.permutation.s_sigma_4.0.to_var_bytes());
            writer.write(&self.permutation.s_sigma_4.1.to_var_bytes());

            writer.write(&self.permutation.linear_evaluations.to_var_bytes());

            writer.write(&self.v_h_coset_8n.to_var_bytes());

            bytes
        }

        /// Deserializes a slice of bytes into a [`ProverKey`].
        pub fn from_slice(bytes: &[u8]) -> Result<ProverKey, Error> {
            let mut buffer = bytes;
            let n = u64::from_reader(&mut buffer)? as usize;
            let evaluations_size = u64::from_reader(&mut buffer)? as usize;
            // let domain = crate::fft::EvaluationDomain::new(4 * size)?;
            // TODO: By creating this we can avoid including the
            // EvaluationDomain inside Evaluations. See:
            // dusk-network/plonk#436

            let poly_from_reader =
                |buf: &mut &[u8]| -> Result<Polynomial, Error> {
                    let serialized_poly_len =
                        u64::from_reader(buf)? as usize * BlsScalar::SIZE;
                    // If the announced len is zero, simply return an empty poly
                    // and leave the buffer intact.
                    if serialized_poly_len == 0 {
                        return Ok(Polynomial { coeffs: vec![] });
                    }
                    let (a, b) = buf.split_at(serialized_poly_len);
                    let poly = Polynomial::from_slice(a);
                    *buf = b;

                    poly
                };

            let evals_from_reader =
                |buf: &mut &[u8]| -> Result<Evaluations, Error> {
                    let (a, b) = buf.split_at(evaluations_size);
                    let eval = Evaluations::from_slice(a);
                    *buf = b;

                    eval
                };

            let q_m_poly = poly_from_reader(&mut buffer)?;
            let q_m_evals = evals_from_reader(&mut buffer)?;
            let q_m = (q_m_poly, q_m_evals);

            let q_l_poly = poly_from_reader(&mut buffer)?;
            let q_l_evals = evals_from_reader(&mut buffer)?;
            let q_l = (q_l_poly, q_l_evals);

            let q_r_poly = poly_from_reader(&mut buffer)?;
            let q_r_evals = evals_from_reader(&mut buffer)?;
            let q_r = (q_r_poly, q_r_evals);

            let q_o_poly = poly_from_reader(&mut buffer)?;
            let q_o_evals = evals_from_reader(&mut buffer)?;
            let q_o = (q_o_poly, q_o_evals);

            let q_4_poly = poly_from_reader(&mut buffer)?;
            let q_4_evals = evals_from_reader(&mut buffer)?;
            let q_4 = (q_4_poly, q_4_evals);

            let q_c_poly = poly_from_reader(&mut buffer)?;
            let q_c_evals = evals_from_reader(&mut buffer)?;
            let q_c = (q_c_poly, q_c_evals);

            let q_arith_poly = poly_from_reader(&mut buffer)?;
            let q_arith_evals = evals_from_reader(&mut buffer)?;
            let q_arith = (q_arith_poly, q_arith_evals);

            let q_logic_poly = poly_from_reader(&mut buffer)?;
            let q_logic_evals = evals_from_reader(&mut buffer)?;
            let q_logic = (q_logic_poly, q_logic_evals);

            let q_range_poly = poly_from_reader(&mut buffer)?;
            let q_range_evals = evals_from_reader(&mut buffer)?;
            let q_range = (q_range_poly, q_range_evals);

            let q_fixed_group_add_poly = poly_from_reader(&mut buffer)?;
            let q_fixed_group_add_evals = evals_from_reader(&mut buffer)?;
            let q_fixed_group_add =
                (q_fixed_group_add_poly, q_fixed_group_add_evals);

            let q_variable_group_add_poly = poly_from_reader(&mut buffer)?;
            let q_variable_group_add_evals = evals_from_reader(&mut buffer)?;
            let q_variable_group_add =
                (q_variable_group_add_poly, q_variable_group_add_evals);

            let s_sigma_1_poly = poly_from_reader(&mut buffer)?;
            let s_sigma_1_evals = evals_from_reader(&mut buffer)?;
            let s_sigma_1 = (s_sigma_1_poly, s_sigma_1_evals);

            let s_sigma_2_poly = poly_from_reader(&mut buffer)?;
            let s_sigma_2_evals = evals_from_reader(&mut buffer)?;
            let s_sigma_2 = (s_sigma_2_poly, s_sigma_2_evals);

            let s_sigma_3_poly = poly_from_reader(&mut buffer)?;
            let s_sigma_3_evals = evals_from_reader(&mut buffer)?;
            let s_sigma_3 = (s_sigma_3_poly, s_sigma_3_evals);

            let s_sigma_4_poly = poly_from_reader(&mut buffer)?;
            let s_sigma_4_evals = evals_from_reader(&mut buffer)?;
            let s_sigma_4 = (s_sigma_4_poly, s_sigma_4_evals);

            let perm_linear_evaluations = evals_from_reader(&mut buffer)?;

            let v_h_coset_8n = evals_from_reader(&mut buffer)?;

            let arithmetic = arithmetic::ProverKey {
                q_m,
                q_l: q_l.clone(),
                q_r: q_r.clone(),
                q_o,
                q_c: q_c.clone(),
                q_4,
                q_arith,
            };

            let logic = logic::ProverKey {
                q_logic,
                q_c: q_c.clone(),
            };

            let range = range::ProverKey { q_range };

            let fixed_base = ecc::scalar_mul::fixed_base::ProverKey {
                q_l,
                q_r,
                q_c,
                q_fixed_group_add,
            };

            let permutation = permutation::ProverKey {
                s_sigma_1,
                s_sigma_2,
                s_sigma_3,
                s_sigma_4,
                linear_evaluations: perm_linear_evaluations,
            };

            let variable_base = ecc::curve_addition::ProverKey {
                q_variable_group_add,
            };

            let prover_key = ProverKey {
                n,
                arithmetic,
                logic,
                range,
                fixed_base,
                variable_base,
                permutation,
                v_h_coset_8n,
            };

            Ok(prover_key)
        }

        pub(crate) fn v_h_coset_8n(&self) -> &Evaluations {
            &self.v_h_coset_8n
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg(test)]
mod test {
    use super::alloc::ProverKey;
    use super::*;
    use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use rand_core::OsRng;
    use zero_bls12_381::Fr as BlsScalar;
    use zero_crypto::behave::Group;

    fn rand_poly_eval(n: usize) -> (Polynomial, Evaluations) {
        let polynomial = Polynomial::rand(n, &mut OsRng);
        (polynomial, rand_evaluations(n))
    }

    fn rand_evaluations(n: usize) -> Evaluations {
        let domain = EvaluationDomain::new(4 * n).unwrap();
        let values: Vec<_> =
            (0..4 * n).map(|_| BlsScalar::random(&mut OsRng)).collect();

        Evaluations::from_vec_and_domain(values, domain)
    }

    #[test]
    fn test_serialize_deserialize_prover_key() {
        let n = 1 << 11;

        let q_m = rand_poly_eval(n);
        let q_l = rand_poly_eval(n);
        let q_r = rand_poly_eval(n);
        let q_o = rand_poly_eval(n);
        let q_c = rand_poly_eval(n);
        let q_4 = rand_poly_eval(n);
        let q_arith = rand_poly_eval(n);

        let q_logic = rand_poly_eval(n);

        let q_range = rand_poly_eval(n);

        let q_fixed_group_add = rand_poly_eval(n);

        let q_variable_group_add = rand_poly_eval(n);

        let s_sigma_1 = rand_poly_eval(n);
        let s_sigma_2 = rand_poly_eval(n);
        let s_sigma_3 = rand_poly_eval(n);
        let s_sigma_4 = rand_poly_eval(n);
        let linear_evaluations = rand_evaluations(n);

        let v_h_coset_8n = rand_evaluations(n);

        let arithmetic = arithmetic::ProverKey {
            q_m,
            q_l: q_l.clone(),
            q_r: q_r.clone(),
            q_o,
            q_c: q_c.clone(),
            q_4,
            q_arith,
        };

        let logic = logic::ProverKey {
            q_logic,
            q_c: q_c.clone(),
        };

        let range = range::ProverKey { q_range };

        let fixed_base = ecc::scalar_mul::fixed_base::ProverKey {
            q_fixed_group_add,
            q_l,
            q_r,
            q_c,
        };

        let permutation = permutation::ProverKey {
            s_sigma_1,
            s_sigma_2,
            s_sigma_3,
            s_sigma_4,
            linear_evaluations,
        };

        let variable_base = ecc::curve_addition::ProverKey {
            q_variable_group_add,
        };

        let prover_key = ProverKey {
            n,
            arithmetic,
            logic,
            fixed_base,
            range,
            variable_base,
            permutation,
            v_h_coset_8n,
        };

        let prover_key_bytes = prover_key.to_var_bytes();
        let pk = ProverKey::from_slice(&prover_key_bytes).unwrap();

        assert_eq!(pk, prover_key);
        assert_eq!(pk.to_var_bytes(), prover_key.to_var_bytes());
    }

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
