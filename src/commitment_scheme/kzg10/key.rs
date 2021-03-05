// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Key module contains the utilities and data structures
//! that support the generation and usage of Commit and
//! Opening keys.
use super::{Commitment, Proof};
use crate::{
    error::Error, fft::Polynomial, transcript::TranscriptProtocol, util,
};
use dusk_bls12_381::{
    multiscalar_mul::msm_variable_base, BlsScalar, G1Affine, G1Projective,
    G2Affine, G2Prepared,
};
use dusk_bytes::{DeserializableSlice, Serializable};
use merlin::Transcript;

/// CommitKey is used to commit to a polynomial which is bounded by the
/// max_degree.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitKey {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to
    /// `degree`.
    pub(crate) powers_of_g: Vec<G1Affine>,
}

impl CommitKey {
    /// Serialize the `CommitKey` into bytes.
    ///
    /// This operation is designed to store the raw representation of the
    /// contents of the CommitKey. Therefore, the size of the bytes outputed
    /// by this function is expected to be the double than the one that
    /// `CommitKey::to_bytes()`.
    ///
    /// # Note
    /// This function should be used when we want to serialize the CommitKey
    /// allowing a really fast deserialization later.
    /// This functions output should not be used by the regular
    /// `CommitKey::from_bytes()` fn.
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(8 + self.powers_of_g.len() * G1Affine::RAW_SIZE);

        let len = self.powers_of_g.len() as u64;
        let len = len.to_le_bytes();
        bytes.extend_from_slice(&len);

        self.powers_of_g
            .iter()
            .for_each(|g| bytes.extend_from_slice(&g.to_raw_bytes()));

        bytes
    }

    /// Deserialize `CommitKey` from a set of bytes created by
    /// `to_bytes_unchecked`
    ///
    /// The bytes source is expected to be trusted and no check will be
    /// performed reggarding the points security
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        if bytes.len() < 9 {
            return Self {
                powers_of_g: vec![],
            };
        }

        let mut len = [0u8; 8];
        len.copy_from_slice(&bytes[..8]);
        let len = u64::from_le_bytes(len);

        let powers_of_g = bytes[8..]
            .chunks_exact(G1Affine::RAW_SIZE)
            .zip(0..len)
            .map(|(c, _)| G1Affine::from_slice_unchecked(c))
            .collect();

        Self { powers_of_g }
    }

    /// Serialises the commitment Key to a byte slice.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.powers_of_g
            .iter()
            .map(|item| item.to_bytes().to_vec())
            .flatten()
            .collect()
    }

    /// Deserialise a slice of bytes into a Commit Key struct performing
    /// security and consistency checks for each point that the bytes
    /// contain.
    ///
    /// # Note
    /// This function can be really slow if the `CommitKey` has a certain
    /// degree/size. If the bytes come from a trusted source such as a local
    /// file, we recommend to use `from_slice_unchecked()` and
    /// `to_raw_bytes()`.
    pub fn from_bytes(bytes: &[u8]) -> Result<CommitKey, Error> {
        let powers_of_g = bytes
            .chunks(G1Affine::SIZE)
            .map(|chunk| G1Affine::from_slice(chunk))
            .collect::<Result<Vec<G1Affine>, dusk_bytes::Error>>()?;

        Ok(CommitKey { powers_of_g })
    }

    /// Returns the maximum degree polynomial that you can commit to.
    pub(crate) fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }

    /// Truncates the commit key to a lower max degree.
    /// Returns an error if the truncated degree is zero or if the truncated
    /// degree is larger than the max degree of the commit key.
    pub(crate) fn truncate(
        &self,
        mut truncated_degree: usize,
    ) -> Result<CommitKey, Error> {
        if truncated_degree == 1 {
            truncated_degree += 1;
        }
        // Check that the truncated degree is not zero
        if truncated_degree == 0 {
            return Err(Error::TruncatedDegreeIsZero);
        }

        // Check that max degree is less than truncated degree
        if truncated_degree > self.max_degree() {
            return Err(Error::TruncatedDegreeTooLarge);
        }

        let truncated_powers = Self {
            powers_of_g: self.powers_of_g[..=truncated_degree].to_vec(),
        };

        Ok(truncated_powers)
    }

    /// Checks whether the polynomial we are committing to:
    /// - Has zero degree
    /// - Has a degree which is more than the max supported degree
    ///
    /// Returns an error if any of the above conditions are true.
    fn check_commit_degree_is_within_bounds(
        &self,
        poly_degree: usize,
    ) -> Result<(), Error> {
        match (poly_degree == 0, poly_degree > self.max_degree()) {
            (true, _) => Err(Error::PolynomialDegreeIsZero),
            (false, true) => Err(Error::PolynomialDegreeTooLarge),
            (false, false) => Ok(()),
        }
    }

    /// Commits to a polynomial returning the corresponding `Commitment`.
    ///
    /// Returns an error if the polynomial's degree is more than the max degree
    /// of the commit key.
    pub(crate) fn commit(
        &self,
        polynomial: &Polynomial,
    ) -> Result<Commitment, Error> {
        // Check whether we can safely commit to this polynomial
        self.check_commit_degree_is_within_bounds(polynomial.degree())?;

        // Compute commitment
        let commitment =
            msm_variable_base(&self.powers_of_g, &polynomial.coeffs);
        Ok(Commitment::from_projective(commitment))
    }

    /// Computes a single witness for multiple polynomials at the same point, by
    /// taking a random linear combination of the individual witnesses.
    /// We apply the same optimisation mentioned in when computing each witness;
    /// removing f(z).
    pub(crate) fn compute_aggregate_witness(
        &self,
        polynomials: &[Polynomial],
        point: &BlsScalar,
        transcript: &mut Transcript,
    ) -> Polynomial {
        let challenge = transcript.challenge_scalar(b"aggregate_witness");
        let powers = util::powers_of(&challenge, polynomials.len() - 1);

        assert_eq!(powers.len(), polynomials.len());

        let numerator: Polynomial = polynomials
            .iter()
            .zip(powers.iter())
            .map(|(poly, challenge)| poly * challenge)
            .sum();
        numerator.ruffini(*point)
    }
}

/// Opening Key is used to verify opening proofs made about a committed
/// polynomial.
#[derive(Clone, Debug)]
pub struct OpeningKey {
    /// The generator of G1.
    pub(crate) g: G1Affine,
    /// The generator of G2.
    pub(crate) h: G2Affine,
    /// \beta times the above generator of G2.
    pub(crate) beta_h: G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub(crate) prepared_h: G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub(crate) prepared_beta_h: G2Prepared,
}

impl Serializable<{ G1Affine::SIZE + 2 * G2Affine::SIZE }> for OpeningKey {
    type Error = dusk_bytes::Error;
    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;
        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        // This can't fail therefore we don't care about the Result nor use it.
        writer.write(&self.g.to_bytes());
        writer.write(&self.h.to_bytes());
        writer.write(&self.beta_h.to_bytes());

        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<OpeningKey, Self::Error> {
        let mut buffer = &buf[..];
        let g = G1Affine::from_reader(&mut buffer)?;
        let h = G2Affine::from_reader(&mut buffer)?;
        let beta_h = G2Affine::from_reader(&mut buffer)?;

        Ok(OpeningKey::new(g, h, beta_h))
    }
}

impl OpeningKey {
    pub(crate) fn new(
        g: G1Affine,
        h: G2Affine,
        beta_h: G2Affine,
    ) -> OpeningKey {
        let prepared_h: G2Prepared = G2Prepared::from(h);
        let prepared_beta_h = G2Prepared::from(beta_h);
        OpeningKey {
            g,
            h,
            beta_h,
            prepared_beta_h,
            prepared_h,
        }
    }

    /// Checks whether a batch of polynomials evaluated at different points,
    /// returned their specified value.
    pub(crate) fn batch_check(
        &self,
        points: &[BlsScalar],
        proofs: &[Proof],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        let mut total_c = G1Projective::identity();
        let mut total_w = G1Projective::identity();

        let challenge = transcript.challenge_scalar(b"batch"); // XXX: Verifier can add their own randomness at this point
        let powers = util::powers_of(&challenge, proofs.len() - 1);
        // Instead of multiplying g and gamma_g in each turn, we simply
        // accumulate their coefficients and perform a final
        // multiplication at the end.
        let mut g_multiplier = BlsScalar::zero();

        for ((proof, challenge), point) in proofs.iter().zip(powers).zip(points)
        {
            let mut c = G1Projective::from(proof.commitment_to_polynomial.0);
            let w = proof.commitment_to_witness.0;
            c += w * point;
            g_multiplier += challenge * proof.evaluated_point;

            total_c += c * challenge;
            total_w += w * challenge;
        }
        total_c -= self.g * g_multiplier;

        let affine_total_w = G1Affine::from(-total_w);
        let affine_total_c = G1Affine::from(total_c);

        let pairing = dusk_bls12_381::multi_miller_loop(&[
            (&affine_total_w, &self.prepared_beta_h),
            (&affine_total_c, &self.prepared_h),
        ])
        .final_exponentiation();

        if pairing != dusk_bls12_381::Gt::identity() {
            return Err(Error::PairingCheckFailure);
        };
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::commitment_scheme::kzg10::{AggregateProof, PublicParameters};
    use crate::fft::Polynomial;
    use dusk_bls12_381::BlsScalar;
    use merlin::Transcript;

    // Checks that a polynomial `p` was evaluated at a point `z` and returned
    // the value specified `v`. ie. v = p(z).
    fn check(op_key: &OpeningKey, point: BlsScalar, proof: Proof) -> bool {
        let inner_a: G1Affine = (proof.commitment_to_polynomial.0
            - (op_key.g * proof.evaluated_point))
            .into();

        let inner_b: G2Affine = (op_key.beta_h - (op_key.h * point)).into();
        let prepared_inner_b = G2Prepared::from(-inner_b);

        let pairing = dusk_bls12_381::multi_miller_loop(&[
            (&inner_a, &op_key.prepared_h),
            (&proof.commitment_to_witness.0, &prepared_inner_b),
        ])
        .final_exponentiation();

        pairing == dusk_bls12_381::Gt::identity()
    }

    // Creates an opening proof that a polynomial `p` was correctly evaluated at
    // p(z) and produced the value `v`. ie v = p(z).
    // Returns an error if the polynomials degree is too large.
    fn open_single(
        ck: &CommitKey,
        polynomial: &Polynomial,
        value: &BlsScalar,
        point: &BlsScalar,
    ) -> Result<Proof, Error> {
        let witness_poly = compute_single_witness(polynomial, point);
        Ok(Proof {
            commitment_to_witness: ck.commit(&witness_poly)?,
            evaluated_point: *value,
            commitment_to_polynomial: ck.commit(polynomial)?,
        })
    }

    // Creates an opening proof that multiple polynomials were evaluated at the
    // same point and that each evaluation produced the correct evaluation
    // point. Returns an error if any of the polynomial's degrees are too
    // large.
    fn open_multiple(
        ck: &CommitKey,
        polynomials: &[Polynomial],
        evaluations: Vec<BlsScalar>,
        point: &BlsScalar,
        transcript: &mut Transcript,
    ) -> Result<AggregateProof, Error> {
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            polynomial_commitments.push(ck.commit(poly)?)
        }

        // Compute the aggregate witness for polynomials
        let witness_poly =
            ck.compute_aggregate_witness(polynomials, point, transcript);

        // Commit to witness polynomial
        let witness_commitment = ck.commit(&witness_poly)?;

        let aggregate_proof = AggregateProof {
            commitment_to_witness: witness_commitment,
            evaluated_points: evaluations,
            commitments_to_polynomials: polynomial_commitments,
        };
        Ok(aggregate_proof)
    }

    // For a given polynomial `p` and a point `z`, compute the witness
    // for p(z) using Ruffini's method for simplicity.
    // The Witness is the quotient of f(x) - f(z) / x-z.
    // However we note that the quotient polynomial is invariant under the value
    // f(z) ie. only the remainder changes. We can therefore compute the
    // witness as f(x) / x - z and only use the remainder term f(z) during
    // verification.
    fn compute_single_witness(
        polynomial: &Polynomial,
        point: &BlsScalar,
    ) -> Polynomial {
        // Computes `f(x) / x-z`, returning it as the witness poly
        polynomial.ruffini(*point)
    }

    // Creates a proving key and verifier key based on a specified degree
    fn setup_test(degree: usize) -> (CommitKey, OpeningKey) {
        let srs =
            PublicParameters::setup(degree, &mut rand::thread_rng()).unwrap();
        srs.trim(degree).unwrap()
    }
    #[test]
    fn test_basic_commit() {
        let degree = 25;
        let (ck, opening_key) = setup_test(degree);
        let point = BlsScalar::from(10);

        let poly = Polynomial::rand(degree, &mut rand::thread_rng());
        let value = poly.evaluate(&point);

        let proof = open_single(&ck, &poly, &value, &point).unwrap();

        let ok = check(&opening_key, point, proof);
        assert!(ok);
    }
    #[test]
    fn test_batch_verification() {
        let degree = 25;
        let (ck, vk) = setup_test(degree);

        let point_a = BlsScalar::from(10);
        let point_b = BlsScalar::from(11);

        // Compute secret polynomial a
        let poly_a = Polynomial::rand(degree, &mut rand::thread_rng());
        let value_a = poly_a.evaluate(&point_a);
        let proof_a = open_single(&ck, &poly_a, &value_a, &point_a).unwrap();
        assert!(check(&vk, point_a, proof_a));

        // Compute secret polynomial b
        let poly_b = Polynomial::rand(degree, &mut rand::thread_rng());
        let value_b = poly_b.evaluate(&point_b);
        let proof_b = open_single(&ck, &poly_b, &value_b, &point_b).unwrap();
        assert!(check(&vk, point_b, proof_b));

        assert!(vk
            .batch_check(
                &[point_a, point_b],
                &[proof_a, proof_b],
                &mut Transcript::new(b""),
            )
            .is_ok());
    }
    #[test]
    fn test_aggregate_witness() {
        let max_degree = 27;
        let (ck, opening_key) = setup_test(max_degree);
        let point = BlsScalar::from(10);

        // Committer's View
        let aggregated_proof = {
            // Compute secret polynomials and their evaluations
            let poly_a = Polynomial::rand(25, &mut rand::thread_rng());
            let poly_a_eval = poly_a.evaluate(&point);

            let poly_b = Polynomial::rand(26 + 1, &mut rand::thread_rng());
            let poly_b_eval = poly_b.evaluate(&point);

            let poly_c = Polynomial::rand(27, &mut rand::thread_rng());
            let poly_c_eval = poly_c.evaluate(&point);

            open_multiple(
                &ck,
                &[poly_a, poly_b, poly_c],
                vec![poly_a_eval, poly_b_eval, poly_c_eval],
                &point,
                &mut Transcript::new(b"agg_flatten"),
            )
            .unwrap()
        };

        // Verifier's View
        let ok = {
            let flattened_proof =
                aggregated_proof.flatten(&mut Transcript::new(b"agg_flatten"));
            check(&opening_key, point, flattened_proof)
        };

        assert!(ok);
    }

    #[test]
    fn test_batch_with_aggregation() {
        let max_degree = 28;
        let (ck, opening_key) = setup_test(max_degree);
        let point_a = BlsScalar::from(10);
        let point_b = BlsScalar::from(11);

        // Committer's View
        let (aggregated_proof, single_proof) = {
            // Compute secret polynomial and their evaluations
            let poly_a = Polynomial::rand(25, &mut rand::thread_rng());
            let poly_a_eval = poly_a.evaluate(&point_a);

            let poly_b = Polynomial::rand(26, &mut rand::thread_rng());
            let poly_b_eval = poly_b.evaluate(&point_a);

            let poly_c = Polynomial::rand(27, &mut rand::thread_rng());
            let poly_c_eval = poly_c.evaluate(&point_a);

            let poly_d = Polynomial::rand(28, &mut rand::thread_rng());
            let poly_d_eval = poly_d.evaluate(&point_b);

            let aggregated_proof = open_multiple(
                &ck,
                &[poly_a, poly_b, poly_c],
                vec![poly_a_eval, poly_b_eval, poly_c_eval],
                &point_a,
                &mut Transcript::new(b"agg_batch"),
            )
            .unwrap();

            let single_proof =
                open_single(&ck, &poly_d, &poly_d_eval, &point_b).unwrap();

            (aggregated_proof, single_proof)
        };

        // Verifier's View
        let ok = {
            let mut transcript = Transcript::new(b"agg_batch");
            let flattened_proof = aggregated_proof.flatten(&mut transcript);

            opening_key.batch_check(
                &[point_a, point_b],
                &[flattened_proof, single_proof],
                &mut transcript,
            )
        };

        assert!(ok.is_ok());
    }

    #[test]
    fn commit_key_serde() {
        let (commit_key, _) = setup_test(7);
        let ck_bytes = commit_key.into_bytes();
        let ck_bytes_safe = CommitKey::from_bytes(&ck_bytes)
            .expect("CommitKey conversion error");

        assert_eq!(commit_key.powers_of_g, ck_bytes_safe.powers_of_g);
    }

    #[test]
    fn opening_key_dusk_bytes() {
        let (_, opening_key) = setup_test(7);
        let ok_bytes = opening_key.to_bytes();
        let obtained_key = OpeningKey::from_bytes(&ok_bytes)
            .expect("CommitKey conversion error");

        assert_eq!(opening_key.to_bytes(), obtained_key.to_bytes());
    }

    #[test]
    fn commit_key_bytes_unchecked() {
        let (ck, _) = setup_test(7);

        let ck_p = unsafe {
            let bytes = ck.to_raw_bytes();
            CommitKey::from_slice_unchecked(&bytes)
        };

        assert_eq!(ck, ck_p);
    }
}
