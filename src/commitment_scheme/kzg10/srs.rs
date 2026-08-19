// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The Public Parameters can also be referred to as the Structured Reference
//! String (SRS).
use alloc::vec::Vec;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
use dusk_bls12_381::{G1Affine, G1Projective, G2Affine};
use dusk_bytes::{DeserializableSlice, Serializable};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize, Serialize,
    ser::{ScratchSpace, Serializer},
};

#[cfg(feature = "rkyv-impl")]
use super::key::OpeningKeyRkyv;
use super::key::{CommitKey, OpeningKey};
use crate::error::Error;
use crate::util;

/// The Public Parameters can also be referred to as the Structured Reference
/// String (SRS). It is available to both the prover and verifier and allows the
/// verifier to efficiently verify and make claims about polynomials up to and
/// including a configured degree.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub struct PublicParameters {
    /// Key used to generate proofs for composed circuits.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) commit_key: CommitKey,
    /// Key used to verify proofs for composed circuits.
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    #[cfg_attr(feature = "rkyv-impl", with(OpeningKeyRkyv))]
    pub(crate) opening_key: OpeningKey,
}

impl PublicParameters {
    /// The maximum degree is the degree of the constraint system + 6,
    /// because adding the blinding factors requires some extra elements
    /// for the SRS: +1 per each wire (we have 4 wires), plus +2 for the
    /// permutation polynomial
    pub(crate) const ADDED_BLINDING_DEGREE: usize = 6;

    /// Setup generates the public parameters using a random number generator.
    /// This method will in most cases be used for testing and exploration.
    /// In reality, a `Trusted party` or a `Multiparty Computation` will be used
    /// to generate the SRS. Returns an error if the configured degree is less
    /// than one.
    pub fn setup<R: RngCore + CryptoRng>(
        mut max_degree: usize,
        mut rng: &mut R,
    ) -> Result<PublicParameters, Error> {
        // Cannot commit to constants
        if max_degree < 1 {
            return Err(Error::DegreeIsZero);
        }

        // we update the degree to match the required one (n + 6)
        max_degree += Self::ADDED_BLINDING_DEGREE;

        // Generate the secret scalar x
        let x = util::random_nonzero_bls_scalar(&mut rng);

        // Compute powers of x up to and including x^max_degree
        let powers_of_x = util::powers_of(&x, max_degree);

        // Powers of G1 that will be used to commit to a specified polynomial
        let g = util::random_g1_point(&mut rng);
        let powers_of_g: Vec<G1Projective> =
            util::slow_multiscalar_mul_single_base(&powers_of_x, g);
        assert_eq!(powers_of_g.len(), max_degree + 1);

        // Normalize all projective points
        let mut normalized_g = vec![G1Affine::identity(); max_degree + 1];
        G1Projective::batch_normalize(&powers_of_g, &mut normalized_g);

        // Compute x_2 = x*h element and stored cached elements for verifying
        // multiple proofs.
        let h: G2Affine = util::random_g2_point(&mut rng).into();
        let x_2: G2Affine = (h * x).into();

        Ok(PublicParameters {
            commit_key: CommitKey {
                powers_of_g: normalized_g,
            },
            opening_key: OpeningKey::try_new(g.into(), h, x_2)?,
        })
    }

    /// Serialize the [`PublicParameters`] into bytes.
    ///
    /// This operation is designed to store the raw representation of the
    /// contents of the PublicParameters. Therefore, the size of the bytes
    /// outputed by this function is expected to be the double than the one
    /// that [`PublicParameters::to_var_bytes`].
    ///
    /// # Note
    /// This function should be used when we want to serialize the
    /// PublicParameters allowing a really fast deserialization later.
    /// This functions output should not be used by the regular
    /// [`PublicParameters::from_slice`] fn.
    pub fn to_raw_var_bytes(&self) -> Vec<u8> {
        let mut bytes = self.opening_key.to_bytes().to_vec();
        bytes.extend(&self.commit_key.to_raw_var_bytes());

        bytes
    }

    /// Deserialize [`PublicParameters`] from a set of bytes created by
    /// [`PublicParameters::to_raw_var_bytes`].
    ///
    /// The bytes source is expected to be trusted. The opening key is always
    /// decoded and validated, while the commit-key points remain unchecked.
    ///
    /// # Safety
    /// This function will not produce any memory errors but can lead to the
    /// generation of an invalid commit key. To make sure this does not happen,
    /// the input bytes must match bytes generated by this library. The function
    /// panics if the opening key is malformed.
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        unsafe {
            let opening_key = &bytes[..OpeningKey::SIZE];
            let opening_key = OpeningKey::from_slice(opening_key)
                .expect("Error at OpeningKey deserialization");

            let commit_key = &bytes[OpeningKey::SIZE..];
            let commit_key = CommitKey::from_slice_unchecked(commit_key);

            Self {
                commit_key,
                opening_key,
            }
        }
    }

    /// Serializes a [`PublicParameters`] struct into a slice of bytes.
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes = self.opening_key.to_bytes().to_vec();
        bytes.extend(self.commit_key.to_var_bytes().iter());
        bytes
    }

    /// Deserialize a slice of bytes into a Public Parameter struct performing
    /// security and consistency checks for each point that the bytes
    /// contain.
    ///
    /// # Note
    /// This function can be really slow if the [`PublicParameters`] have a
    /// certain degree. If the bytes come from a trusted source such as a
    /// local file, we recommend to use
    /// [`PublicParameters::from_slice_unchecked`] and
    /// [`PublicParameters::to_raw_var_bytes`].
    pub fn from_slice(bytes: &[u8]) -> Result<PublicParameters, Error> {
        if bytes.len() <= OpeningKey::SIZE {
            return Err(Error::NotEnoughBytes);
        }
        let mut buf = bytes;
        let opening_key = OpeningKey::from_reader(&mut buf)?;
        let commit_key = CommitKey::from_slice(buf)?;

        let pp = PublicParameters {
            commit_key,
            opening_key,
        };

        Ok(pp)
    }

    /// Trim truncates the [`PublicParameters`] to allow the prover to commit to
    /// polynomials up to the and including the truncated degree.
    /// Returns the [`CommitKey`] and [`OpeningKey`] used to generate and verify
    /// proofs.
    ///
    /// Returns an error if the truncated degree is larger than the public
    /// parameters configured degree.
    pub(crate) fn trim(
        &self,
        truncated_degree: usize,
    ) -> Result<(CommitKey, OpeningKey), Error> {
        let truncated_prover_key = self
            .commit_key
            .truncate(truncated_degree + Self::ADDED_BLINDING_DEGREE)?;
        Ok((truncated_prover_key, self.opening_key.clone()))
    }

    /// Max degree specifies the largest Polynomial
    /// that this prover key can commit to.
    pub fn max_degree(&self) -> usize {
        self.commit_key.max_degree()
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use dusk_bls12_381::BlsScalar;
    #[cfg(feature = "rkyv-impl")]
    use dusk_bls12_381::G2Prepared;
    #[cfg(feature = "rkyv-impl")]
    use merlin::Transcript;
    use rand_core::OsRng;

    #[cfg(feature = "rkyv-impl")]
    use super::super::proof::Proof;
    use super::*;
    #[cfg(feature = "rkyv-impl")]
    use crate::fft::Polynomial;
    #[cfg(feature = "rkyv-impl")]
    use crate::prelude::{Circuit, Compiler, Composer};

    #[cfg(feature = "rkyv-impl")]
    #[derive(Default)]
    struct ArchivedParametersCircuit;

    #[cfg(feature = "rkyv-impl")]
    impl Circuit for ArchivedParametersCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let bit = composer.append_witness(BlsScalar::one());
            composer.component_boolean(bit);
            Ok(())
        }
    }

    #[cfg(feature = "rkyv-impl")]
    #[derive(Archive, Serialize)]
    #[archive(bound(serialize = "__S: Serializer + ScratchSpace"))]
    struct LegacyOpeningKey {
        #[omit_bounds]
        g: G1Affine,
        #[omit_bounds]
        h: G2Affine,
        #[omit_bounds]
        x_h: G2Affine,
        #[omit_bounds]
        prepared_h: G2Prepared,
        #[omit_bounds]
        prepared_x_h: G2Prepared,
    }

    #[cfg(feature = "rkyv-impl")]
    #[derive(Archive, Serialize)]
    #[archive(bound(serialize = "__S: Serializer + ScratchSpace"))]
    struct LegacyPublicParameters {
        #[omit_bounds]
        commit_key: CommitKey,
        #[omit_bounds]
        opening_key: LegacyOpeningKey,
    }

    #[cfg(feature = "rkyv-impl")]
    #[derive(Archive, Serialize)]
    #[archive(bound(serialize = "__S: Serializer + ScratchSpace"))]
    struct RawCommitKey {
        #[omit_bounds]
        powers_of_g: Vec<G1Affine>,
    }

    #[cfg(feature = "rkyv-impl")]
    #[derive(Archive, Serialize)]
    #[archive(bound(serialize = "__S: Serializer + ScratchSpace"))]
    struct RawPublicParameters {
        #[omit_bounds]
        commit_key: RawCommitKey,
        #[omit_bounds]
        #[with(OpeningKeyRkyv)]
        opening_key: OpeningKey,
    }

    #[cfg(feature = "rkyv-impl")]
    impl From<&PublicParameters> for LegacyPublicParameters {
        fn from(parameters: &PublicParameters) -> Self {
            let key = &parameters.opening_key;
            Self {
                commit_key: parameters.commit_key.clone(),
                opening_key: LegacyOpeningKey {
                    g: key.g,
                    h: key.h,
                    x_h: key.x_h,
                    prepared_h: key.prepared_h.clone(),
                    prepared_x_h: key.prepared_x_h.clone(),
                },
            }
        }
    }

    #[cfg(feature = "rkyv-impl")]
    impl From<&PublicParameters> for RawPublicParameters {
        fn from(parameters: &PublicParameters) -> Self {
            Self {
                commit_key: RawCommitKey {
                    powers_of_g: parameters.commit_key.powers_of_g.clone(),
                },
                opening_key: parameters.opening_key.clone(),
            }
        }
    }

    #[cfg(feature = "rkyv-impl")]
    fn off_curve_g1() -> G1Affine {
        let mut bytes =
            rkyv::to_bytes::<_, 256>(&G1Affine::generator()).unwrap();
        bytes[0] ^= 1;
        let point = rkyv::from_bytes::<G1Affine>(&bytes).unwrap();
        assert!(!bool::from(point.is_on_curve()));
        point
    }

    #[cfg(feature = "rkyv-impl")]
    fn off_curve_g2() -> G2Affine {
        let mut bytes =
            rkyv::to_bytes::<_, 256>(&G2Affine::generator()).unwrap();
        bytes[0] ^= 1;
        let point = rkyv::from_bytes::<G2Affine>(&bytes).unwrap();
        assert!(!bool::from(point.is_on_curve()));
        point
    }

    #[cfg(feature = "rkyv-impl")]
    fn non_torsion_g1() -> G1Affine {
        let mut bytes = [0u8; G1Affine::SIZE];
        bytes[0] = 0x80;
        let point = Option::<G1Affine>::from(
            G1Affine::from_compressed_unchecked(&bytes),
        )
        .unwrap();
        assert!(!bool::from(point.is_torsion_free()));
        point
    }

    #[cfg(feature = "rkyv-impl")]
    fn non_torsion_g2() -> G2Affine {
        let mut bytes = [0u8; G2Affine::SIZE];
        bytes[0] = 0x80;
        bytes[G2Affine::SIZE - 1] = 2;
        let point = Option::<G2Affine>::from(
            G2Affine::from_compressed_unchecked(&bytes),
        )
        .unwrap();
        assert!(!bool::from(point.is_torsion_free()));
        point
    }

    #[cfg(feature = "rkyv-impl")]
    fn assert_archived_opening_key_rejected(
        mutate: impl FnOnce(&mut OpeningKey),
    ) {
        let mut pp = PublicParameters::setup(8, &mut OsRng).unwrap();
        mutate(&mut pp.opening_key);

        let bytes = rkyv::to_bytes::<_, 256>(&pp).unwrap();
        assert!(rkyv::from_bytes::<PublicParameters>(&bytes).is_err());
    }

    #[cfg(feature = "rkyv-impl")]
    fn assert_archived_commit_key_rejected(
        mutate: impl FnOnce(&mut CommitKey),
    ) {
        let mut pp = PublicParameters::setup(8, &mut OsRng).unwrap();
        mutate(&mut pp.commit_key);

        let bytes = rkyv::to_bytes::<_, 256>(&pp).unwrap();
        assert_archived_parameters_rejected_without_panic(&bytes);
    }

    #[cfg(feature = "rkyv-impl")]
    fn first_archived_commitment_point_offset(bytes: &[u8]) -> usize {
        let parameters =
            unsafe { rkyv::archived_root::<PublicParameters>(bytes) };
        let point = &parameters.commit_key.powers_of_g[0];
        point as *const _ as usize - bytes.as_ptr() as usize
    }

    #[cfg(feature = "rkyv-impl")]
    fn assert_archived_parameters_rejected_without_panic(bytes: &[u8]) {
        let result = std::panic::catch_unwind(|| {
            rkyv::from_bytes::<PublicParameters>(bytes)
        });
        assert!(result.is_ok(), "checked deserialization must not panic");
        assert!(
            result.expect("checked above").is_err(),
            "malformed parameters must be rejected"
        );
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_rejects_legacy_raw_commitment_key_layout_without_panicking() {
        let pp = PublicParameters::setup(8, &mut OsRng).unwrap();
        let bytes =
            rkyv::to_bytes::<_, 256>(&RawPublicParameters::from(&pp)).unwrap();

        assert_archived_parameters_rejected_without_panic(&bytes);
    }

    #[cfg(feature = "rkyv-impl")]
    fn assert_archived_prepared_point_rebuilt(
        mutate: impl FnOnce(&mut OpeningKey),
    ) {
        let mut pp = PublicParameters::setup(8, &mut OsRng).unwrap();
        let (commit_key, _) = pp.trim(2).unwrap();
        let point = BlsScalar::from(7u64);
        let polynomial = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(3u64),
            BlsScalar::from(5u64),
            BlsScalar::from(11u64),
        ]);
        let evaluated_point = polynomial.evaluate(&point);
        let witness = polynomial.ruffini(point);
        let proof = Proof {
            commitment_to_witness: commit_key.commit(&witness).unwrap(),
            evaluated_point,
            commitment_to_polynomial: commit_key.commit(&polynomial).unwrap(),
        };

        mutate(&mut pp.opening_key);
        let bytes = rkyv::to_bytes::<_, 256>(&pp).unwrap();
        let decoded = rkyv::from_bytes::<PublicParameters>(&bytes).unwrap();

        decoded
            .opening_key
            .batch_check(
                &[point],
                &[proof],
                &mut Transcript::new(b"archived-opening-key"),
            )
            .expect("deserialization must rebuild the prepared point");
    }

    #[test]
    fn test_powers_of() {
        let x = BlsScalar::from(10u64);
        let degree = 100u64;

        let powers_of_x = util::powers_of(&x, degree as usize);

        for (i, x_i) in powers_of_x.iter().enumerate() {
            assert_eq!(*x_i, x.pow(&[i as u64, 0, 0, 0]))
        }

        let last_element = powers_of_x.last().unwrap();
        assert_eq!(*last_element, x.pow(&[degree, 0, 0, 0]))
    }

    #[test]
    fn test_serialize_deserialize_public_parameter() {
        let pp = PublicParameters::setup(1 << 7, &mut OsRng).unwrap();

        let got_pp = PublicParameters::from_slice(&pp.to_var_bytes()).unwrap();

        assert_eq!(got_pp.commit_key.powers_of_g, pp.commit_key.powers_of_g);
        assert_eq!(got_pp.opening_key.g, pp.opening_key.g);
        assert_eq!(got_pp.opening_key.h, pp.opening_key.h);
        assert_eq!(got_pp.opening_key.x_h, pp.opening_key.x_h);
    }

    #[test]
    fn public_parameters_bytes_unchecked() {
        let pp = PublicParameters::setup(1 << 7, &mut OsRng).unwrap();

        let pp_p = unsafe {
            let bytes = pp.to_raw_var_bytes();
            PublicParameters::from_slice_unchecked(&bytes)
        };

        assert_eq!(pp.commit_key, pp_p.commit_key);
        assert_eq!(pp.opening_key.g, pp_p.opening_key.g);
        assert_eq!(pp.opening_key.h, pp_p.opening_key.h);
        assert_eq!(pp.opening_key.x_h, pp_p.opening_key.x_h);
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_rejects_empty_archived_commit_key() {
        assert_archived_commit_key_rejected(|key| key.powers_of_g.clear());
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_rejects_invalid_archived_commit_key_points() {
        let pp = PublicParameters::setup(8, &mut OsRng).unwrap();
        let mut bytes = rkyv::to_bytes::<_, 256>(&pp).unwrap();
        let point = first_archived_commitment_point_offset(&bytes);
        bytes[point] &= 0x7f;
        assert_archived_parameters_rejected_without_panic(&bytes);

        assert_archived_commit_key_rejected(|key| {
            key.powers_of_g[0] = non_torsion_g1();
        });
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_commit_key_round_trip_compiles_circuit() {
        let pp = PublicParameters::setup(16, &mut OsRng).unwrap();
        let bytes = rkyv::to_bytes::<_, 256>(&pp).unwrap();
        let decoded = rkyv::from_bytes::<PublicParameters>(&bytes).unwrap();

        assert_eq!(decoded.commit_key, pp.commit_key);
        Compiler::compile::<ArchivedParametersCircuit>(
            &decoded,
            b"archived-commit-key",
        )
        .expect("validated public parameters must compile a circuit");
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_rejects_degenerate_archived_opening_key() {
        assert_archived_opening_key_rejected(|key| {
            key.g = G1Affine::identity();
        });
        assert_archived_opening_key_rejected(|key| {
            key.h = G2Affine::identity();
        });
        assert_archived_opening_key_rejected(|key| {
            key.x_h = G2Affine::identity();
        });
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_rejects_invalid_archived_opening_key_points() {
        assert_archived_opening_key_rejected(|key| key.g = off_curve_g1());
        assert_archived_opening_key_rejected(|key| key.g = non_torsion_g1());
        assert_archived_opening_key_rejected(|key| key.h = off_curve_g2());
        assert_archived_opening_key_rejected(|key| key.x_h = non_torsion_g2());
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_rebuilds_unarchived_prepared_points() {
        assert_archived_prepared_point_rebuilt(|key| {
            key.prepared_h = G2Prepared::from(G2Affine::identity());
        });
        assert_archived_prepared_point_rebuilt(|key| {
            key.prepared_x_h = G2Prepared::from(G2Affine::identity());
        });
    }

    #[cfg(feature = "rkyv-impl")]
    #[test]
    fn rkyv_archive_omits_prepared_points_and_rejects_legacy_layout() {
        let pp = PublicParameters::setup(8, &mut OsRng).unwrap();
        let bytes = rkyv::to_bytes::<_, 256>(&pp).unwrap();
        let legacy =
            rkyv::to_bytes::<_, 256>(&LegacyPublicParameters::from(&pp))
                .unwrap();

        let saved = legacy
            .len()
            .checked_sub(bytes.len())
            .expect("new opening-key archive unexpectedly exceeds legacy size");
        assert!(saved >= 39_000, "expected a ~39 KB saving, got {saved}");
        assert!(rkyv::from_bytes::<PublicParameters>(&legacy).is_err());
        assert!(rkyv::from_bytes::<PublicParameters>(&bytes).is_ok());
    }
}
