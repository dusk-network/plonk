// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

pub mod arithmetic;
pub mod ecc;
pub mod logic;
pub mod lookup;
pub mod permutation;
pub mod range;

use crate::fft::Evaluations;
use crate::transcript::TranscriptProtocol;
use anyhow::{Error, Result};
use merlin::Transcript;
use serde::de::Visitor;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

/// PLONK circuit proving key
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProverKey {
    /// Circuit size
    pub n: usize,
    /// ProverKey for arithmetic gate
    pub arithmetic: arithmetic::ProverKey,
    /// ProverKey for logic gate
    pub logic: logic::ProverKey,
    /// ProverKey for range gate
    pub range: range::ProverKey,
    /// ProverKey for lookup gates
    pub lookup: lookup::ProverKey,
    /// ProverKey for fixed base curve addition gates
    pub fixed_base: ecc::scalar_mul::fixed_base::ProverKey,
    /// ProverKey for permutation checks
    pub permutation: permutation::ProverKey,
    /// ProverKey for variable base curve addition gates
    pub variable_base: ecc::curve_addition::ProverKey,
    /// ProverKey for lookup operations
    pub lookup: lookup::ProverKey,

    // Pre-processes the 4n Evaluations for the vanishing polynomial, so they do not
    // need to be computed at the proving stage.
    // Note: With this, we can combine all parts of the quotient polynomial in their evaluation phase and
    // divide by the quotient polynomial without having to perform IFFT
    pub(crate) v_h_coset_4n: Evaluations,
}

/// Plookup circuit verification key
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct VerifierKey {
    /// Circuit size
    pub n: usize,
    /// VerifierKey for arithmetic gates
    pub arithmetic: arithmetic::VerifierKey,
    /// VerifierKey for logic gates
    pub logic: logic::VerifierKey,
    /// VerifierKey for range gates
    pub range: range::VerifierKey,
    /// VerifierKey for fixed base curve addition gates
    pub fixed_base: ecc::scalar_mul::fixed_base::VerifierKey,
    /// VerifierKey for variable base curve addition gates
    pub variable_base: ecc::curve_addition::VerifierKey,
    /// VerifierKey for lookup operations
    pub lookup: lookup::VerifierKey,
    /// VerifierKey for permutation checks
    pub permutation: permutation::VerifierKey,
}

impl VerifierKey {
    /// Serialises a VerifierKey to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        use crate::serialisation::{write_commitment, write_u64};

        let mut bytes = Vec::with_capacity(VerifierKey::serialised_size());

        // Circuit size
        // Assuming that circuits will not exceed 2^64 we cast `usize` to `u64`
        write_u64(self.n as u64, &mut bytes);

        // Arithmetic

        write_commitment(&self.arithmetic.q_m, &mut bytes);
        write_commitment(&self.arithmetic.q_l, &mut bytes);
        write_commitment(&self.arithmetic.q_r, &mut bytes);
        write_commitment(&self.arithmetic.q_o, &mut bytes);
        write_commitment(&self.arithmetic.q_4, &mut bytes);
        write_commitment(&self.arithmetic.q_c, &mut bytes);
        write_commitment(&self.arithmetic.q_arith, &mut bytes);

        // Logic
        write_commitment(&self.logic.q_logic, &mut bytes);

        // Range
        write_commitment(&self.range.q_range, &mut bytes);

        // Fixed base scalar mul
        write_commitment(&self.fixed_base.q_fixed_group_add, &mut bytes);

        // Curve addition
        write_commitment(&self.variable_base.q_variable_group_add, &mut bytes);

        // Lookup
        write_commitment(&self.lookup.q_lookup, &mut bytes);

        // Perm
        write_commitment(&self.permutation.left_sigma, &mut bytes);
        write_commitment(&self.permutation.right_sigma, &mut bytes);
        write_commitment(&self.permutation.out_sigma, &mut bytes);
        write_commitment(&self.permutation.fourth_sigma, &mut bytes);

        bytes
    }

    /// Deserialise a slice of bytes into a VerifierKey
    pub fn from_bytes(bytes: &[u8]) -> Result<VerifierKey, Error> {
        use crate::serialisation::{read_commitment, read_u64};

        let (n, rest) = read_u64(bytes)?;

        let (q_m, rest) = read_commitment(rest)?;
        let (q_l, rest) = read_commitment(rest)?;
        let (q_r, rest) = read_commitment(rest)?;
        let (q_o, rest) = read_commitment(rest)?;
        let (q_4, rest) = read_commitment(rest)?;
        let (q_c, rest) = read_commitment(rest)?;
        let (q_arith, rest) = read_commitment(rest)?;

        let (q_logic, rest) = read_commitment(rest)?;

        let (q_range, rest) = read_commitment(rest)?;

        let (q_fixed_group_add, rest) = read_commitment(rest)?;

        let (q_variable_group_add, rest) = read_commitment(rest)?;

        let (q_lookup, rest) = read_commitment(rest)?;

        let (left_sigma, rest) = read_commitment(rest)?;
        let (right_sigma, rest) = read_commitment(rest)?;
        let (out_sigma, rest) = read_commitment(rest)?;
        let (fourth_sigma, _) = read_commitment(rest)?;

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
            q_fixed_group_add,
            q_l,
            q_r,
        };

        let variable_base = ecc::curve_addition::VerifierKey {
            q_variable_group_add,
        };

        let lookup = lookup::VerifierKey { q_lookup };

        let permutation = permutation::VerifierKey {
            left_sigma,
            right_sigma,
            out_sigma,
            fourth_sigma,
        };

        let verifier_key = VerifierKey {
            n: n as usize,
            arithmetic,
            logic,
            range,
            variable_base,
            fixed_base,
            permutation,
            lookup,
        };
        Ok(verifier_key)
    }

    /// Return the serialized size of a [`VerifierKey`]
    pub const fn serialised_size() -> usize {
        const N_SIZE: usize = 8;
        const NUM_COMMITMENTS: usize = 15;
        const COMMITMENT_SIZE: usize = 48;
        N_SIZE + NUM_COMMITMENTS * COMMITMENT_SIZE
    }

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
        transcript.append_commitment(b"q_fixed_group_add", &self.fixed_base.q_fixed_group_add);
        transcript.append_commitment(b"q_lookup", &self.lookup.q_lookup);

        transcript.append_commitment(b"left_sigma", &self.permutation.left_sigma);
        transcript.append_commitment(b"right_sigma", &self.permutation.right_sigma);
        transcript.append_commitment(b"out_sigma", &self.permutation.out_sigma);
        transcript.append_commitment(b"fourth_sigma", &self.permutation.fourth_sigma);

        // Append circuit size to transcript
        transcript.circuit_domain_sep(self.n as u64);
    }
}

impl ProverKey {
    /// Serialises a ProverKey struct into bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        use crate::serialisation::{write_evaluations, write_polynomial, write_u64};

        let mut bytes = Vec::with_capacity(ProverKey::serialised_size(self.n));

        write_u64(self.n as u64, &mut bytes);

        // Arithmetic
        write_polynomial(&self.arithmetic.q_m.0, &mut bytes);
        write_evaluations(&self.arithmetic.q_m.1, &mut bytes);

        write_polynomial(&self.arithmetic.q_l.0, &mut bytes);
        write_evaluations(&self.arithmetic.q_l.1, &mut bytes);

        write_polynomial(&self.arithmetic.q_r.0, &mut bytes);
        write_evaluations(&self.arithmetic.q_r.1, &mut bytes);

        write_polynomial(&self.arithmetic.q_o.0, &mut bytes);
        write_evaluations(&self.arithmetic.q_o.1, &mut bytes);

        write_polynomial(&self.arithmetic.q_4.0, &mut bytes);
        write_evaluations(&self.arithmetic.q_4.1, &mut bytes);

        write_polynomial(&self.arithmetic.q_c.0, &mut bytes);
        write_evaluations(&self.arithmetic.q_c.1, &mut bytes);

        write_polynomial(&self.arithmetic.q_arith.0, &mut bytes);
        write_evaluations(&self.arithmetic.q_arith.1, &mut bytes);

        // Logic
        write_polynomial(&self.logic.q_logic.0, &mut bytes);
        write_evaluations(&self.logic.q_logic.1, &mut bytes);

        // Range
        write_polynomial(&self.range.q_range.0, &mut bytes);
        write_evaluations(&self.range.q_range.1, &mut bytes);

        // BlsScalar multiplication
        write_polynomial(&self.fixed_base.q_fixed_group_add.0, &mut bytes);
        write_evaluations(&self.fixed_base.q_fixed_group_add.1, &mut bytes);

        // Curve addition
        write_polynomial(&self.variable_base.q_variable_group_add.0, &mut bytes);

        // Lookup
        write_polynomial(&self.lookup.q_lookup.0, &mut bytes);
        write_evaluations(&self.lookup.q_lookup.1, &mut bytes);

        // Permutation
        write_polynomial(&self.permutation.left_sigma.0, &mut bytes);
        write_evaluations(&self.permutation.left_sigma.1, &mut bytes);

        write_polynomial(&self.permutation.right_sigma.0, &mut bytes);
        write_evaluations(&self.permutation.right_sigma.1, &mut bytes);

        write_polynomial(&self.permutation.out_sigma.0, &mut bytes);
        write_evaluations(&self.permutation.out_sigma.1, &mut bytes);

        write_polynomial(&self.permutation.fourth_sigma.0, &mut bytes);
        write_evaluations(&self.permutation.fourth_sigma.1, &mut bytes);
        write_evaluations(&self.permutation.linear_evaluations, &mut bytes);

        write_evaluations(&self.v_h_coset_4n, &mut bytes);

        bytes
    }
    /// Deserialises a slice of bytes into a ProverKey
    pub fn from_bytes(bytes: &[u8]) -> Result<ProverKey, Error> {
        use crate::serialisation::{read_evaluations, read_polynomial, read_u64};

        let (n, rest) = read_u64(bytes)?;
        let domain = crate::fft::EvaluationDomain::new((4 * n) as usize).unwrap();

        let (q_m_poly, rest) = read_polynomial(&rest)?;
        let (q_m_evals, rest) = read_evaluations(domain, &rest)?;
        let q_m = (q_m_poly, q_m_evals);

        let (q_l_poly, rest) = read_polynomial(&rest)?;
        let (q_l_evals, rest) = read_evaluations(domain, &rest)?;
        let q_l = (q_l_poly, q_l_evals);

        let (q_r_poly, rest) = read_polynomial(&rest)?;
        let (q_r_evals, rest) = read_evaluations(domain, &rest)?;
        let q_r = (q_r_poly, q_r_evals);

        let (q_o_poly, rest) = read_polynomial(&rest)?;
        let (q_o_evals, rest) = read_evaluations(domain, &rest)?;
        let q_o = (q_o_poly, q_o_evals);

        let (q_4_poly, rest) = read_polynomial(&rest)?;
        let (q_4_evals, rest) = read_evaluations(domain, &rest)?;
        let q_4 = (q_4_poly, q_4_evals);

        let (q_c_poly, rest) = read_polynomial(&rest)?;
        let (q_c_evals, rest) = read_evaluations(domain, &rest)?;
        let q_c = (q_c_poly, q_c_evals);

        let (q_arith_poly, rest) = read_polynomial(&rest)?;
        let (q_arith_evals, rest) = read_evaluations(domain, &rest)?;
        let q_arith = (q_arith_poly, q_arith_evals);

        let (q_logic_poly, rest) = read_polynomial(&rest)?;
        let (q_logic_evals, rest) = read_evaluations(domain, &rest)?;
        let q_logic = (q_logic_poly, q_logic_evals);

        let (q_range_poly, rest) = read_polynomial(&rest)?;
        let (q_range_evals, rest) = read_evaluations(domain, &rest)?;
        let q_range = (q_range_poly, q_range_evals);

        let (q_fixed_group_add_poly, rest) = read_polynomial(&rest)?;
        let (q_fixed_group_add_evals, rest) = read_evaluations(domain, &rest)?;
        let q_fixed_group_add = (q_fixed_group_add_poly, q_fixed_group_add_evals);

        let (q_variable_group_add_poly, rest) = read_polynomial(&rest)?;
        let (q_variable_group_add_evals, rest) = read_evaluations(domain, &rest)?;
        let q_variable_group_add = (q_variable_group_add_poly, q_variable_group_add_evals);

        let (q_lookup_poly, rest) = read_polynomial(&rest)?;
        let (q_lookup_evals, rest) = read_evaluations(domain, &rest)?;
        let q_lookup = (q_lookup_poly, q_lookup_evals);

        let (left_sigma_poly, rest) = read_polynomial(&rest)?;
        let (left_sigma_evals, rest) = read_evaluations(domain, &rest)?;
        let left_sigma = (left_sigma_poly, left_sigma_evals);

        let (right_sigma_poly, rest) = read_polynomial(&rest)?;
        let (right_sigma_evals, rest) = read_evaluations(domain, &rest)?;
        let right_sigma = (right_sigma_poly, right_sigma_evals);

        let (out_sigma_poly, rest) = read_polynomial(&rest)?;
        let (out_sigma_evals, rest) = read_evaluations(domain, &rest)?;
        let out_sigma = (out_sigma_poly, out_sigma_evals);

        let (fourth_sigma_poly, rest) = read_polynomial(&rest)?;
        let (fourth_sigma_evals, rest) = read_evaluations(domain, &rest)?;
        let fourth_sigma = (fourth_sigma_poly, fourth_sigma_evals);
        let (linear_evaluations, rest) = read_evaluations(domain, rest)?;

        let (v_h_coset_4n, _) = read_evaluations(domain, rest)?;

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

        let lookup = lookup::ProverKey { q_lookup };

        let permutation = permutation::ProverKey {
            left_sigma,
            right_sigma,
            out_sigma,
            fourth_sigma,
            linear_evaluations,
        };

        let variable_base = ecc::curve_addition::ProverKey {
            q_variable_group_add,
        };

        let prover_key = ProverKey {
            n: n as usize,
            arithmetic,
            logic,
            range,
            lookup,
            fixed_base,
            variable_base,
            lookup,
            permutation,
            v_h_coset_4n,
        };

        Ok(prover_key)
    }

    fn serialised_size(n: usize) -> usize {
        const SIZE_SCALAR: usize = 32;

        const NUM_POLYNOMIALS: usize = 15;
        let num_poly_scalars = n;

        const NUM_EVALUATIONS: usize = 16;
        let num_eval_scalars = 4 * n;

        (NUM_POLYNOMIALS * num_poly_scalars * SIZE_SCALAR)
            + (NUM_EVALUATIONS * num_eval_scalars * SIZE_SCALAR)
    }

    pub(crate) fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fft::{EvaluationDomain, Polynomial};
    use dusk_bls12_381::BlsScalar;

    fn rand_poly_eval(n: usize) -> (Polynomial, Evaluations) {
        let polynomial = Polynomial::rand(n, &mut rand::thread_rng());
        (polynomial, rand_evaluations(n))
    }

    fn rand_evaluations(n: usize) -> Evaluations {
        let domain = EvaluationDomain::new(4 * n).unwrap();
        let values: Vec<_> = (0..4 * n)
            .map(|_| BlsScalar::random(&mut rand::thread_rng()))
            .collect();
        let evaluations = Evaluations::from_vec_and_domain(values, domain);
        evaluations
    }

    #[test]
    fn test_serialise_deserialise_prover_key() {
        let n = 2usize.pow(5);

        let q_m = rand_poly_eval(n);
        let q_l = rand_poly_eval(n);
        let q_r = rand_poly_eval(n);
        let q_o = rand_poly_eval(n);
        let q_c = rand_poly_eval(n);
        let q_4 = rand_poly_eval(n);
        let q_arith = rand_poly_eval(n);

        let q_logic = rand_poly_eval(n);

        let q_range = rand_poly_eval(n);
        
        let q_lookup = rand_poly_eval(n);

        let q_fixed_group_add = rand_poly_eval(n);

        let q_variable_group_add = rand_poly_eval(n);

        let left_sigma = rand_poly_eval(n);
        let right_sigma = rand_poly_eval(n);
        let out_sigma = rand_poly_eval(n);
        let fourth_sigma = rand_poly_eval(n);
        let linear_evaluations = rand_evaluations(n);

        let v_h_coset_4n = rand_evaluations(n);

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
            left_sigma,
            right_sigma,
            out_sigma,
            fourth_sigma,
            linear_evaluations,
        };

        let variable_base = ecc::curve_addition::ProverKey {
            q_variable_group_add,
        };

        let prover_key = ProverKey {
            arithmetic,
            logic,
            fixed_base,
            range,
            variable_base,
            permutation,
            v_h_coset_4n,
            n,
        };

        let prover_key_bytes = prover_key.to_bytes();
        let pk = ProverKey::from_bytes(&prover_key_bytes).unwrap();

        assert_eq!(pk, prover_key);
    }

    #[test]
    fn test_serialise_deserialise_verifier_key() {
        use crate::commitment_scheme::kzg10::Commitment;
        use dusk_bls12_381::G1Affine;

        let n = 2usize.pow(5);

        let q_m = Commitment::from_affine(G1Affine::generator());
        let q_l = Commitment::from_affine(G1Affine::generator());
        let q_r = Commitment::from_affine(G1Affine::generator());
        let q_o = Commitment::from_affine(G1Affine::generator());
        let q_c = Commitment::from_affine(G1Affine::generator());
        let q_4 = Commitment::from_affine(G1Affine::generator());
        let q_arith = Commitment::from_affine(G1Affine::generator());

        let q_range = Commitment::from_affine(G1Affine::generator());

        let q_fixed_group_add = Commitment::from_affine(G1Affine::generator());
        let q_variable_group_add = Commitment::from_affine(G1Affine::generator());

        let q_logic = Commitment::from_affine(G1Affine::generator());

        let left_sigma = Commitment::from_affine(G1Affine::generator());
        let right_sigma = Commitment::from_affine(G1Affine::generator());
        let out_sigma = Commitment::from_affine(G1Affine::generator());
        let fourth_sigma = Commitment::from_affine(G1Affine::generator());

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
            left_sigma,
            right_sigma,
            out_sigma,
            fourth_sigma,
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
