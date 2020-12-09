// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The Public Parameters can also be referred to as the Structured Reference String (SRS).
use super::{
    errors::KZG10Errors,
    key::{CommitKey, OpeningKey},
};
use crate::util;
use anyhow::{Error, Result};
use dusk_bls12_381::{G1Affine, G1Projective, G2Affine};
use rand_core::RngCore;

use serde::de::Visitor;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

/// The Public Parameters can also be referred to as the Structured Reference String (SRS).
/// It is available to both the prover and verifier and allows the verifier to
/// efficiently verify and make claims about polynomials up to and including a configured degree.
#[derive(Debug)]
pub struct PublicParameters {
    /// Key used to generate proofs for composed circuits.
    pub commit_key: CommitKey,
    /// Key used to verify proofs for composed circuits.
    pub opening_key: OpeningKey,
}

impl_serde!(PublicParameters);

impl PublicParameters {
    /// Setup generates the public parameters using a random number generator.
    /// This method will in most cases be used for testing and exploration.
    /// In reality, a `Trusted party` or a `Multiparty Computation` will used to generate the SRS.
    /// Returns an error if the configured degree is less than one.
    pub fn setup<R: RngCore>(
        max_degree: usize,
        mut rng: &mut R,
    ) -> Result<PublicParameters, Error> {
        // Cannot commit to constants
        if max_degree < 1 {
            return Err(KZG10Errors::DegreeIsZero.into());
        }

        // Generate the secret scalar beta
        let beta = util::random_scalar(&mut rng);

        // Compute powers of beta up to and including beta^max_degree
        let powers_of_beta = util::powers_of(&beta, max_degree);

        // Powers of G1 that will be used to commit to a specified polynomial
        let g = util::random_g1_point(&mut rng);
        let powers_of_g: Vec<G1Projective> =
            util::slow_multiscalar_mul_single_base(&powers_of_beta, g);
        assert_eq!(powers_of_g.len(), max_degree + 1);

        // Normalise all projective points
        let mut normalised_g = vec![G1Affine::identity(); max_degree + 1];
        G1Projective::batch_normalize(&powers_of_g, &mut normalised_g);

        // Compute beta*G2 element and stored cached elements for verifying multiple proofs.
        let h: G2Affine = util::random_g2_point(&mut rng).into();
        let beta_h: G2Affine = (h * beta).into();

        Ok(PublicParameters {
            commit_key: CommitKey {
                powers_of_g: normalised_g,
            },
            opening_key: OpeningKey::new(g.into(), h, beta_h),
        })
    }

    /// Serialises a [`PublicParameters`] struct into a slice of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.opening_key.to_bytes().to_vec();
        bytes.extend(self.commit_key.to_bytes());
        bytes
    }

    /// Deserialise a slice of bytes into a Public Parameter struct
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicParameters, Error> {
        let opening_key_bytes = &bytes[0..OpeningKey::serialized_size()];
        let commit_key_bytes = &bytes[OpeningKey::serialized_size()..];

        let opening_key = OpeningKey::from_bytes(opening_key_bytes)?;
        let commit_key = CommitKey::from_bytes(commit_key_bytes)?;

        let pp = PublicParameters {
            opening_key,
            commit_key,
        };

        Ok(pp)
    }

    /// Trim truncates the prover key to allow the prover to commit to polynomials up to the
    /// and including the truncated degree.
    /// Returns an error if the truncated degree is larger than the public parameters configured degree.
    pub fn trim(&self, truncated_degree: usize) -> Result<(CommitKey, OpeningKey), Error> {
        let truncated_prover_key = self.commit_key.truncate(truncated_degree)?;
        let opening_key = self.opening_key.clone();
        Ok((truncated_prover_key, opening_key))
    }

    /// Max degree specifies the largest polynomial that this prover key can commit to.
    pub fn max_degree(&self) -> usize {
        self.commit_key.max_degree()
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use dusk_bls12_381::BlsScalar;
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
    fn test_serialise_deserialise_public_parameter() {
        let pp = PublicParameters::setup(100, &mut rand::thread_rng()).unwrap();

        let got_pp = PublicParameters::from_bytes(&pp.to_bytes()).unwrap();

        assert_eq!(got_pp.commit_key.powers_of_g, pp.commit_key.powers_of_g);
        assert_eq!(got_pp.opening_key.g, pp.opening_key.g);
        assert_eq!(got_pp.opening_key.h, pp.opening_key.h);
        assert_eq!(got_pp.opening_key.beta_h, pp.opening_key.beta_h);
    }
}
