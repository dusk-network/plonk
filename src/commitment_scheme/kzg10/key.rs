// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Key module contains the utilities and data structures
//! that support the generation and usage of Commit and
//! Opening keys.
use alloc::vec::Vec;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
use dusk_bls12_381::multiscalar_mul::msm_variable_base;
use dusk_bls12_381::{BlsScalar, G1Affine, G1Projective, G2Affine, G2Prepared};
use dusk_bytes::{DeserializableSlice, Serializable};
use merlin::Transcript;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Fallible, Serialize,
    ser::{ScratchSpace, Serializer},
    validation::ArchiveContext,
    vec::ArchivedVec,
    with::{ArchiveWith, DeserializeWith, SerializeWith},
};

use super::Commitment;
use super::proof::Proof;
use crate::error::Error;
use crate::fft::Polynomial;
use crate::transcript::TranscriptProtocol;
use crate::util;

/// CommitKey is used to commit to a polynomial which is bounded by the
/// max_degree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitKey {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to
    /// `degree`.
    pub(crate) powers_of_g: Vec<G1Affine>,
}

#[cfg(feature = "rkyv-impl")]
#[derive(Archive, Serialize)]
#[archive(bound(serialize = "__S: Serializer + ScratchSpace"))]
#[doc(hidden)]
pub struct CommitKeyArchive {
    pub(crate) powers_of_g: Vec<[u8; G1Affine::SIZE]>,
}

#[cfg(feature = "rkyv-impl")]
impl From<&CommitKey> for CommitKeyArchive {
    fn from(key: &CommitKey) -> Self {
        Self {
            powers_of_g: key
                .powers_of_g
                .iter()
                .map(G1Affine::to_bytes)
                .collect(),
        }
    }
}

#[cfg(feature = "rkyv-impl")]
#[derive(Debug)]
pub struct InvalidArchivedCommitKey;

#[cfg(feature = "rkyv-impl")]
impl core::fmt::Display for InvalidArchivedCommitKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid archived KZG commitment key")
    }
}

#[cfg(feature = "rkyv-impl")]
impl core::error::Error for InvalidArchivedCommitKey {}

#[cfg(feature = "rkyv-impl")]
fn archived_g1_is_valid(bytes: &[u8; G1Affine::SIZE]) -> bool {
    G1Affine::from_slice(bytes).is_ok()
}

#[cfg(feature = "rkyv-impl")]
fn decode_validated_archived_g1(bytes: &[u8; G1Affine::SIZE]) -> G1Affine {
    // `CheckBytes` has already established subgroup membership. Rebuilding
    // through the canonical encoding still checks its field and flag format,
    // while avoiding a duplicate subgroup check.
    Option::from(G1Affine::from_compressed_unchecked(bytes))
        .expect("commitment key archive must be validated")
}

#[cfg(all(feature = "rkyv-impl", feature = "std"))]
fn archived_commit_key_points_are_valid(
    powers: &ArchivedVec<[u8; G1Affine::SIZE]>,
) -> bool {
    use rayon::prelude::*;

    powers.par_iter().all(archived_g1_is_valid)
}

#[cfg(all(feature = "rkyv-impl", not(feature = "std")))]
fn archived_commit_key_points_are_valid(
    powers: &ArchivedVec<[u8; G1Affine::SIZE]>,
) -> bool {
    powers.iter().all(archived_g1_is_valid)
}

#[cfg(feature = "rkyv-impl")]
impl<C> CheckBytes<C> for ArchivedCommitKeyArchive
where
    C: ArchiveContext + ?Sized,
    C::Error: bytecheck::Error,
{
    type Error = InvalidArchivedCommitKey;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        let powers = unsafe {
            ArchivedVec::<[u8; G1Affine::SIZE]>::check_bytes(
                core::ptr::addr_of!((*value).powers_of_g),
                context,
            )
        }
        .map_err(|_| InvalidArchivedCommitKey)?;

        if powers.is_empty() {
            return Err(InvalidArchivedCommitKey);
        }

        if !archived_commit_key_points_are_valid(powers) {
            return Err(InvalidArchivedCommitKey);
        }

        Ok(unsafe { &*value })
    }
}

#[cfg(feature = "rkyv-impl")]
impl Archive for CommitKey {
    type Archived = ArchivedCommitKeyArchive;
    type Resolver = CommitKeyArchiveResolver;

    unsafe fn resolve(
        &self,
        pos: usize,
        resolver: Self::Resolver,
        out: *mut Self::Archived,
    ) {
        let (field_pos, field_out) = rkyv::out_field!(out.powers_of_g);
        unsafe {
            ArchivedVec::resolve_from_len(
                self.powers_of_g.len(),
                pos + field_pos,
                resolver.powers_of_g,
                field_out,
            );
        }
    }
}

#[cfg(feature = "rkyv-impl")]
impl<S> Serialize<S> for CommitKey
where
    S: Serializer + ScratchSpace + ?Sized,
{
    fn serialize(
        &self,
        serializer: &mut S,
    ) -> Result<Self::Resolver, S::Error> {
        CommitKeyArchive::from(self).serialize(serializer)
    }
}

#[cfg(feature = "rkyv-impl")]
impl<D> Deserialize<CommitKey, D> for ArchivedCommitKeyArchive
where
    D: Fallible + ?Sized,
{
    fn deserialize(&self, _: &mut D) -> Result<CommitKey, D::Error> {
        #[cfg(feature = "std")]
        let powers_of_g = {
            use rayon::prelude::*;

            self.powers_of_g
                .par_iter()
                .map(decode_validated_archived_g1)
                .collect()
        };
        #[cfg(not(feature = "std"))]
        let powers_of_g = self
            .powers_of_g
            .iter()
            .map(decode_validated_archived_g1)
            .collect();

        Ok(CommitKey { powers_of_g })
    }
}

impl CommitKey {
    /// Serialize the [`CommitKey`] into bytes.
    ///
    /// This operation is designed to store the raw representation of the
    /// contents of the CommitKey. Therefore, the size of the bytes outputed
    /// by this function is expected to be the double than the one that
    /// `CommitKey::to_bytes`.
    ///
    /// # Note
    /// This function should be used when we want to serialize the CommitKey
    /// allowing a really fast deserialization later.
    /// This functions output should not be used by the regular
    /// `CommitKey::from_bytes` fn.
    pub fn to_raw_var_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            u64::SIZE + self.powers_of_g.len() * G1Affine::RAW_SIZE,
        );

        let len = self.powers_of_g.len() as u64;
        let len = len.to_le_bytes();
        bytes.extend_from_slice(&len);

        self.powers_of_g
            .iter()
            .for_each(|g| bytes.extend_from_slice(&g.to_raw_bytes()));

        bytes
    }

    /// Deserialize [`CommitKey`] from a set of bytes created by
    /// [`CommitKey::to_raw_var_bytes`].
    ///
    /// The bytes source is expected to be trusted and no check will be
    /// performed reggarding the points security
    ///
    /// # Safety
    /// This function will not produce any memory errors but can deal to the
    /// generation of invalid or unsafe points/keys. To make sure this does not
    /// happen, the inputed bytes must match the ones that were generated by
    /// the encoding functions of this lib.
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        unsafe {
            let mut len = [0u8; u64::SIZE];
            len.copy_from_slice(&bytes[..u64::SIZE]);
            let len = u64::from_le_bytes(len);

            let powers_of_g = bytes[u64::SIZE..]
                .chunks_exact(G1Affine::RAW_SIZE)
                .zip(0..len)
                .map(|(c, _)| G1Affine::from_slice_unchecked(c))
                .collect();

            Self { powers_of_g }
        }
    }

    /// Deserialize [`CommitKey`] from bytes created by
    /// [`CommitKey::to_raw_var_bytes`] while validating each decoded point.
    pub fn from_raw_var_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < u64::SIZE {
            return Err(Error::NotEnoughBytes);
        }

        let mut len = [0u8; u64::SIZE];
        len.copy_from_slice(&bytes[..u64::SIZE]);
        let len = u64::from_le_bytes(len) as usize;

        if len == 0 {
            return Err(dusk_bytes::Error::InvalidData.into());
        }

        let expected_len = u64::SIZE
            .checked_add(
                len.checked_mul(G1Affine::RAW_SIZE)
                    .ok_or(Error::NotEnoughBytes)?,
            )
            .ok_or(Error::NotEnoughBytes)?;

        if bytes.len() != expected_len {
            return Err(Error::NotEnoughBytes);
        }

        let mut powers_of_g = Vec::with_capacity(len);

        for chunk in bytes[u64::SIZE..].chunks_exact(G1Affine::RAW_SIZE) {
            // Safety: raw-byte chunk size is checked by `chunks_exact`.
            let point = unsafe { G1Affine::from_slice_unchecked(chunk) };
            let point_is_valid =
                bool::from(point.is_on_curve() & point.is_torsion_free());

            if !point_is_valid {
                return Err(Error::PointMalformed);
            }

            powers_of_g.push(point);
        }

        Ok(Self { powers_of_g })
    }

    /// Serializes the [`CommitKey`] into a byte slice.
    pub fn to_var_bytes(&self) -> Vec<u8> {
        self.powers_of_g
            .iter()
            .flat_map(|item| item.to_bytes().to_vec())
            .collect()
    }

    /// Deserialize a slice of bytes into a [`CommitKey`] struct performing
    /// security and consistency checks for each point that the bytes
    /// contain.
    ///
    /// # Note
    /// This function can be really slow if the [`CommitKey`] has a certain
    /// degree/size. If the bytes come from a trusted source such as a local
    /// file, we recommend to use [`CommitKey::from_slice_unchecked`] and
    /// [`CommitKey::to_raw_var_bytes`].
    pub fn from_slice(bytes: &[u8]) -> Result<CommitKey, Error> {
        let powers_of_g = bytes
            .chunks(G1Affine::SIZE)
            .map(G1Affine::from_slice)
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
        match truncated_degree {
            // Check that the truncated degree is not zero
            0 => Err(Error::TruncatedDegreeIsZero),
            // Check that max degree is less than truncated degree
            i if i > self.max_degree() => Err(Error::TruncatedDegreeTooLarge),
            i => {
                if i == 1 {
                    truncated_degree += 1
                };
                let truncated_powers = Self {
                    powers_of_g: self.powers_of_g[..=truncated_degree].to_vec(),
                };
                Ok(truncated_powers)
            }
        }
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
        match poly_degree > self.max_degree() {
            true => Err(Error::PolynomialDegreeTooLarge),
            false => Ok(()),
        }
    }

    /// Commits to a [`Polynomial`] returning the corresponding [`Commitment`].
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
        Ok(Commitment::from(msm_variable_base(
            &self.powers_of_g,
            polynomial,
        )))
    }

    /// Computes a single witness for multiple polynomials at the same point, by
    /// taking a random linear combination of the individual witnesses.
    /// We apply the same optimization mentioned in when computing each witness;
    /// removing f(z).
    pub(crate) fn compute_aggregate_witness(
        polynomials: &[Polynomial],
        point: &BlsScalar,
        v_challenge: &BlsScalar,
    ) -> Polynomial {
        let powers = util::powers_of(v_challenge, polynomials.len() - 1);

        assert_eq!(powers.len(), polynomials.len());

        let numerator: Polynomial = polynomials
            .iter()
            .zip(powers.iter())
            .map(|(poly, v_challenge)| poly * v_challenge)
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
    /// 'x' times the above generator of G2.
    pub(crate) x_h: G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub(crate) prepared_h: G2Prepared,
    /// 'x' times the above generator of G2, prepared for use in pairings.
    pub(crate) prepared_x_h: G2Prepared,
}

#[cfg(feature = "rkyv-impl")]
#[derive(Archive, Serialize)]
pub struct OpeningKeyArchive {
    g: [u8; G1Affine::SIZE],
    h: [u8; G2Affine::SIZE],
    x_h: [u8; G2Affine::SIZE],
}

#[cfg(feature = "rkyv-impl")]
impl From<&OpeningKey> for OpeningKeyArchive {
    fn from(key: &OpeningKey) -> Self {
        Self {
            g: key.g.to_bytes(),
            h: key.h.to_bytes(),
            x_h: key.x_h.to_bytes(),
        }
    }
}

#[cfg(feature = "rkyv-impl")]
fn archived_opening_key_points(
    key: &ArchivedOpeningKeyArchive,
) -> Result<(G1Affine, G2Affine, G2Affine), dusk_bytes::Error> {
    // Checked decoding enforces canonical, on-curve, subgroup points. Opening
    // keys additionally require every source point to be nonidentity.
    let g = G1Affine::from_slice(&key.g)?;
    let h = G2Affine::from_slice(&key.h)?;
    let x_h = G2Affine::from_slice(&key.x_h)?;

    if bool::from(g.is_identity())
        || bool::from(h.is_identity())
        || bool::from(x_h.is_identity())
    {
        return Err(dusk_bytes::Error::InvalidData);
    }

    Ok((g, h, x_h))
}

#[cfg(feature = "rkyv-impl")]
fn decode_archived_opening_key(
    key: &ArchivedOpeningKeyArchive,
) -> Result<OpeningKey, dusk_bytes::Error> {
    let (g, h, x_h) = archived_opening_key_points(key)?;
    let prepared_h = G2Prepared::from(h);
    let prepared_x_h = G2Prepared::from(x_h);

    Ok(OpeningKey {
        g,
        h,
        x_h,
        prepared_h,
        prepared_x_h,
    })
}

#[cfg(feature = "rkyv-impl")]
#[derive(Debug)]
pub struct InvalidArchivedOpeningKey;

#[cfg(feature = "rkyv-impl")]
impl core::fmt::Display for InvalidArchivedOpeningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid archived KZG opening key")
    }
}

#[cfg(feature = "rkyv-impl")]
impl core::error::Error for InvalidArchivedOpeningKey {}

#[cfg(feature = "rkyv-impl")]
impl<C: ?Sized> CheckBytes<C> for ArchivedOpeningKeyArchive {
    type Error = InvalidArchivedOpeningKey;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        _: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        let value = unsafe { &*value };
        archived_opening_key_points(value)
            .map_err(|_| InvalidArchivedOpeningKey)?;
        Ok(value)
    }
}

#[cfg(feature = "rkyv-impl")]
pub(crate) struct OpeningKeyRkyv;

#[cfg(feature = "rkyv-impl")]
impl ArchiveWith<OpeningKey> for OpeningKeyRkyv {
    type Archived = ArchivedOpeningKeyArchive;
    type Resolver = OpeningKeyArchiveResolver;

    unsafe fn resolve_with(
        field: &OpeningKey,
        pos: usize,
        resolver: Self::Resolver,
        out: *mut Self::Archived,
    ) {
        unsafe {
            OpeningKeyArchive::from(field).resolve(pos, resolver, out);
        }
    }
}

#[cfg(feature = "rkyv-impl")]
impl<S> SerializeWith<OpeningKey, S> for OpeningKeyRkyv
where
    S: Serializer + ScratchSpace + ?Sized,
{
    fn serialize_with(
        field: &OpeningKey,
        serializer: &mut S,
    ) -> Result<Self::Resolver, S::Error> {
        OpeningKeyArchive::from(field).serialize(serializer)
    }
}

#[cfg(feature = "rkyv-impl")]
impl<D> DeserializeWith<ArchivedOpeningKeyArchive, OpeningKey, D>
    for OpeningKeyRkyv
where
    D: Fallible + ?Sized,
{
    fn deserialize_with(
        field: &ArchivedOpeningKeyArchive,
        _: &mut D,
    ) -> Result<OpeningKey, D::Error> {
        // Safe deserialization validates the archive through `CheckBytes`
        // before reaching this infallible reconstruction step.
        Ok(decode_archived_opening_key(field)
            .expect("opening key archive must be validated before use"))
    }
}

fn batch_challenge(
    transcript: &mut Transcript,
    points: &[BlsScalar],
    proofs: &[Proof],
) -> BlsScalar {
    transcript.append_message(b"dom-sep", b"kzg10-batch-check-v1");
    transcript.append_u64(b"batch-len", proofs.len() as u64);
    for (point, proof) in points.iter().zip(proofs) {
        transcript.append_scalar(b"batch-point", point);
        transcript.append_commitment(
            b"batch-polynomial-commitment",
            &proof.commitment_to_polynomial,
        );
        transcript.append_scalar(b"batch-evaluation", &proof.evaluated_point);
        transcript.append_commitment(
            b"batch-witness-commitment",
            &proof.commitment_to_witness,
        );
    }
    transcript.challenge_scalar(b"batch-challenge")
}

impl Serializable<{ G1Affine::SIZE + G2Affine::SIZE * 2 }> for OpeningKey {
    type Error = dusk_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use dusk_bytes::Write;
        let mut buf = [0u8; Self::SIZE];
        let mut writer = &mut buf[..];
        // This can't fail therefore we don't care about the Result nor use it.
        writer.write(&self.g.to_bytes());
        writer.write(&self.h.to_bytes());
        writer.write(&self.x_h.to_bytes());

        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut buffer = &buf[..];
        let g = G1Affine::from_reader(&mut buffer)?;
        let h = G2Affine::from_reader(&mut buffer)?;
        let beta_h = G2Affine::from_reader(&mut buffer)?;

        Self::try_new(g, h, beta_h)
    }
}

impl OpeningKey {
    pub(crate) fn try_new(
        g: G1Affine,
        h: G2Affine,
        x_h: G2Affine,
    ) -> Result<OpeningKey, dusk_bytes::Error> {
        let g_valid = bool::from(g.is_on_curve())
            && bool::from(g.is_torsion_free())
            && !bool::from(g.is_identity());
        let h_valid = bool::from(h.is_on_curve())
            && bool::from(h.is_torsion_free())
            && !bool::from(h.is_identity());
        let x_h_valid = bool::from(x_h.is_on_curve())
            && bool::from(x_h.is_torsion_free())
            && !bool::from(x_h.is_identity());

        if !(g_valid && h_valid && x_h_valid) {
            return Err(dusk_bytes::Error::InvalidData);
        }

        let prepared_h = G2Prepared::from(h);
        let prepared_x_h = G2Prepared::from(x_h);
        Ok(OpeningKey {
            g,
            h,
            x_h,
            prepared_h,
            prepared_x_h,
        })
    }

    /// Checks whether a batch of polynomials evaluated at different points
    /// returned their specified values.
    ///
    /// The caller-provided transcript supplies any surrounding protocol
    /// context. This method then binds the batch length and every opening
    /// point, polynomial commitment, evaluation, and witness commitment before
    /// deriving the random linear-combination challenge. The challenge
    /// therefore cannot be known before the complete batch is fixed, and no
    /// additional verifier randomness is required.
    // Retained for planned production batch verification.
    #[allow(dead_code)]
    pub(crate) fn batch_check(
        &self,
        points: &[BlsScalar],
        proofs: &[Proof],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        if proofs.is_empty() || points.len() != proofs.len() {
            return Err(Error::ProofVerificationError);
        }

        let mut total_c = G1Projective::identity();
        let mut total_w = G1Projective::identity();

        let u_challenge = batch_challenge(transcript, points, proofs);
        let powers = util::powers_of(&u_challenge, proofs.len() - 1);
        // Instead of multiplying g and gamma_g in each turn, we simply
        // accumulate their coefficients and perform a final
        // multiplication at the end.
        let mut g_multiplier = BlsScalar::zero();

        for ((proof, u_challenge), point) in
            proofs.iter().zip(powers).zip(points)
        {
            let mut c = G1Projective::from(proof.commitment_to_polynomial.0);
            let w = proof.commitment_to_witness.0;
            c += w * point;
            g_multiplier += u_challenge * proof.evaluated_point;

            total_c += c * u_challenge;
            total_w += w * u_challenge;
        }
        total_c -= self.g * g_multiplier;

        let affine_total_w = G1Affine::from(-total_w);
        let affine_total_c = G1Affine::from(total_c);

        let pairing = dusk_bls12_381::multi_miller_loop(&[
            (&affine_total_w, &self.prepared_x_h),
            (&affine_total_c, &self.prepared_h),
        ])
        .final_exponentiation();

        if pairing != dusk_bls12_381::Gt::identity() {
            return Err(Error::PairingCheckFailure);
        };
        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use dusk_bls12_381::BlsScalar;
    use dusk_bytes::Serializable;
    use merlin::Transcript;
    use rand_core::OsRng;

    use super::*;
    use crate::commitment_scheme::{AggregateProof, PublicParameters};
    use crate::fft::Polynomial;

    // Checks that a polynomial `p` was evaluated at a point `z` and returned
    // the value specified `v`. ie. v = p(z).
    fn check(op_key: &OpeningKey, point: BlsScalar, proof: Proof) -> bool {
        let inner_a: G1Affine = (proof.commitment_to_polynomial.0
            - (op_key.g * proof.evaluated_point))
            .into();

        let inner_b: G2Affine = (op_key.x_h - (op_key.h * point)).into();
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

        let v_challenge = transcript.challenge_scalar(b"v_challenge");

        // Compute the aggregate witness for polynomials
        let witness_poly = CommitKey::compute_aggregate_witness(
            polynomials,
            point,
            &v_challenge,
        );

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
    fn setup_test(degree: usize) -> Result<(CommitKey, OpeningKey), Error> {
        let srs = PublicParameters::setup(degree, &mut OsRng)?;
        srs.trim(degree)
    }
    #[test]
    fn test_commit_rejects_oversized_polynomial() -> Result<(), Error> {
        let degree = 25;
        let (ck, _) = setup_test(degree)?;

        let poly = Polynomial::rand(ck.max_degree() + 1, &mut OsRng);
        assert_eq!(ck.commit(&poly), Err(Error::PolynomialDegreeTooLarge));
        Ok(())
    }
    #[test]
    fn test_basic_commit() -> Result<(), Error> {
        let degree = 25;
        let (ck, opening_key) = setup_test(degree)?;
        let point = BlsScalar::from(10);

        let poly = Polynomial::rand(degree, &mut OsRng);
        let value = poly.evaluate(&point);

        let proof = open_single(&ck, &poly, &value, &point)?;

        let ok = check(&opening_key, point, proof);
        assert!(ok);
        Ok(())
    }
    #[test]
    fn test_batch_verification() -> Result<(), Error> {
        let degree = 25;
        let (ck, vk) = setup_test(degree)?;

        let point_a = BlsScalar::from(10);
        let point_b = BlsScalar::from(11);

        // Compute secret polynomial a
        let poly_a = Polynomial::rand(degree, &mut OsRng);
        let value_a = poly_a.evaluate(&point_a);
        let proof_a = open_single(&ck, &poly_a, &value_a, &point_a)?;
        assert!(check(&vk, point_a, proof_a));

        // Compute secret polynomial b
        let poly_b = Polynomial::rand(degree, &mut OsRng);
        let value_b = poly_b.evaluate(&point_b);
        let proof_b = open_single(&ck, &poly_b, &value_b, &point_b)?;
        assert!(check(&vk, point_b, proof_b));

        vk.batch_check(
            &[point_a, point_b],
            &[proof_a, proof_b],
            &mut Transcript::new(b""),
        )
    }

    #[test]
    fn batch_challenge_binds_the_complete_batch() -> Result<(), Error> {
        let (ck, _) = setup_test(4)?;
        let point = BlsScalar::from(10u64);
        let polynomial = Polynomial::rand(4, &mut OsRng);
        let evaluation = polynomial.evaluate(&point);
        let proof = open_single(&ck, &polynomial, &evaluation, &point)?;

        let derive = |points: &[BlsScalar], proofs: &[Proof]| {
            batch_challenge(
                &mut Transcript::new(b"batch-binding"),
                points,
                proofs,
            )
        };
        let expected = derive(&[point], &[proof]);

        assert_ne!(expected, derive(&[point + BlsScalar::one()], &[proof]));

        let mut changed = proof;
        changed.commitment_to_polynomial = Commitment::default();
        assert_ne!(expected, derive(&[point], &[changed]));

        changed = proof;
        changed.evaluated_point += BlsScalar::one();
        assert_ne!(expected, derive(&[point], &[changed]));

        changed = proof;
        changed.commitment_to_witness = Commitment::default();
        assert_ne!(expected, derive(&[point], &[changed]));

        assert_ne!(expected, derive(&[point, point], &[proof, proof]));

        Ok(())
    }

    #[test]
    fn batch_check_rejects_empty_or_mismatched_batches() -> Result<(), Error> {
        let (_, opening_key) = setup_test(2)?;
        let proof = Proof {
            commitment_to_witness: Commitment::default(),
            evaluated_point: BlsScalar::zero(),
            commitment_to_polynomial: Commitment::default(),
        };

        assert_eq!(
            opening_key.batch_check(
                &[],
                &[],
                &mut Transcript::new(b"empty-batch")
            ),
            Err(Error::ProofVerificationError)
        );
        assert_eq!(
            opening_key.batch_check(
                &[BlsScalar::zero()],
                &[proof, proof],
                &mut Transcript::new(b"mismatched-batch")
            ),
            Err(Error::ProofVerificationError)
        );

        Ok(())
    }

    #[test]
    fn test_aggregate_witness() -> Result<(), Error> {
        let max_degree = 27;
        let (ck, opening_key) = setup_test(max_degree)?;
        let point = BlsScalar::from(10);

        // Committer's View
        let aggregated_proof = {
            // Compute secret polynomials and their evaluations
            let poly_a = Polynomial::rand(25, &mut OsRng);
            let poly_a_eval = poly_a.evaluate(&point);

            let poly_b = Polynomial::rand(26 + 1, &mut OsRng);
            let poly_b_eval = poly_b.evaluate(&point);

            let poly_c = Polynomial::rand(27, &mut OsRng);
            let poly_c_eval = poly_c.evaluate(&point);

            open_multiple(
                &ck,
                &[poly_a, poly_b, poly_c],
                vec![poly_a_eval, poly_b_eval, poly_c_eval],
                &point,
                &mut Transcript::new(b"agg_flatten"),
            )?
        };

        // Verifier's View
        let ok = {
            let transcript = &mut Transcript::new(b"agg_flatten");
            let v_challenge = transcript.challenge_scalar(b"v_challenge");
            let flattened_proof = aggregated_proof.flatten(&v_challenge);
            check(&opening_key, point, flattened_proof)
        };

        assert!(ok);
        Ok(())
    }

    #[test]
    fn test_batch_with_aggregation() -> Result<(), Error> {
        let max_degree = 28;
        let (ck, opening_key) = setup_test(max_degree)?;
        let point_a = BlsScalar::from(10);
        let point_b = BlsScalar::from(11);

        // Committer's View
        let (aggregated_proof, single_proof) = {
            // Compute secret polynomial and their evaluations
            let poly_a = Polynomial::rand(25, &mut OsRng);
            let poly_a_eval = poly_a.evaluate(&point_a);

            let poly_b = Polynomial::rand(26, &mut OsRng);
            let poly_b_eval = poly_b.evaluate(&point_a);

            let poly_c = Polynomial::rand(27, &mut OsRng);
            let poly_c_eval = poly_c.evaluate(&point_a);

            let poly_d = Polynomial::rand(28, &mut OsRng);
            let poly_d_eval = poly_d.evaluate(&point_b);

            let aggregated_proof = open_multiple(
                &ck,
                &[poly_a, poly_b, poly_c],
                vec![poly_a_eval, poly_b_eval, poly_c_eval],
                &point_a,
                &mut Transcript::new(b"agg_batch"),
            )?;

            let single_proof =
                open_single(&ck, &poly_d, &poly_d_eval, &point_b)?;

            (aggregated_proof, single_proof)
        };

        // Verifier's View

        let mut transcript = Transcript::new(b"agg_batch");
        let v_challenge = transcript.challenge_scalar(b"v_challenge");
        let flattened_proof = aggregated_proof.flatten(&v_challenge);

        opening_key.batch_check(
            &[point_a, point_b],
            &[flattened_proof, single_proof],
            &mut transcript,
        )
    }

    #[test]
    fn commit_key_serde() -> Result<(), Error> {
        let (commit_key, _) = setup_test(11)?;
        let ck_bytes = commit_key.to_var_bytes();
        let ck_bytes_safe = CommitKey::from_slice(&ck_bytes)?;

        assert_eq!(commit_key.powers_of_g, ck_bytes_safe.powers_of_g);
        Ok(())
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn commit_key_rkyv_round_trip_rejects_malformed_points() {
        const BASE_FIELD_MODULUS: [u64; 6] = [
            0xb9fe_ffff_ffff_aaab,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ];

        let (commit_key, _) = setup_test(11).unwrap();
        let mut bytes = rkyv::to_bytes::<_, 256>(&commit_key).unwrap();
        let archived = unsafe { rkyv::archived_root::<CommitKey>(&bytes) };
        let point = &archived.powers_of_g[0];
        let point_offset = point as *const _ as usize - bytes.as_ptr() as usize;

        let decoded = rkyv::from_bytes::<CommitKey>(&bytes).unwrap();
        assert_eq!(decoded, commit_key);

        bytes[point_offset] &= 0x7f;
        let result =
            std::panic::catch_unwind(|| rkyv::from_bytes::<CommitKey>(&bytes));
        assert!(result.is_ok(), "checked deserialization must not panic");
        assert!(result.expect("checked above").is_err());

        let point = &mut bytes[point_offset..point_offset + G1Affine::SIZE];
        for (chunk, limb) in point
            .chunks_exact_mut(8)
            .zip(BASE_FIELD_MODULUS.iter().rev())
        {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        point[0] |= 0x80;
        let result =
            std::panic::catch_unwind(|| rkyv::from_bytes::<CommitKey>(&bytes));
        assert!(result.is_ok(), "checked deserialization must not panic");
        assert!(result.expect("checked above").is_err());
    }

    #[test]
    fn opening_key_dusk_bytes() -> Result<(), Error> {
        let (_, opening_key) = setup_test(7)?;
        let ok_bytes = opening_key.to_bytes();
        let obtained_key = OpeningKey::from_bytes(&ok_bytes)?;

        assert_eq!(opening_key.to_bytes(), obtained_key.to_bytes());
        Ok(())
    }

    #[test]
    fn commit_key_bytes_unchecked() -> Result<(), Error> {
        let (ck, _) = setup_test(7)?;

        let ck_p = unsafe {
            let bytes = ck.to_raw_var_bytes();
            CommitKey::from_slice_unchecked(&bytes)
        };

        assert_eq!(ck, ck_p);
        Ok(())
    }

    #[test]
    fn commit_key_bytes_raw_checked() -> Result<(), Error> {
        let (ck, _) = setup_test(7)?;

        let bytes = ck.to_raw_var_bytes();
        let decoded = CommitKey::from_raw_var_bytes(&bytes)?;

        assert_eq!(ck, decoded);
        Ok(())
    }

    #[test]
    fn commit_key_bytes_raw_checked_rejects_truncated() -> Result<(), Error> {
        let (ck, _) = setup_test(7)?;
        let mut bytes = ck.to_raw_var_bytes();
        bytes.pop();

        assert!(matches!(
            CommitKey::from_raw_var_bytes(&bytes),
            Err(Error::NotEnoughBytes)
        ));
        Ok(())
    }

    #[test]
    fn commit_key_bytes_raw_checked_rejects_empty() {
        assert!(matches!(
            CommitKey::from_raw_var_bytes(&0u64.to_le_bytes()),
            Err(Error::BytesError(dusk_bytes::Error::InvalidData))
        ));
    }

    #[test]
    fn commit_key_bytes_raw_checked_rejects_malformed_point() {
        let mut bytes = vec![0u8; u64::SIZE + G1Affine::RAW_SIZE];
        bytes[0] = 1; // one point in little-endian length prefix

        assert!(matches!(
            CommitKey::from_raw_var_bytes(&bytes),
            Err(Error::PointMalformed)
        ));
    }
}
