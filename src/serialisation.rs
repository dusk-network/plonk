// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::commitment_scheme::kzg10::Commitment;
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use anyhow::{Error, Result};
use dusk_bls12_381::{BlsScalar, G1Affine, G2Affine};
use thiserror::Error;

/// Defines all of the possible Serialisation errors
#[derive(Error, Debug)]
pub enum SerialisationErrors {
    #[error("There are not enough bytes to perform deserialisation")]
    NotEnoughBytes,
    #[error("Cannot decompress point, as it is not in a canonical format")]
    PointMalformed,
    #[error("Cannot deserialise scalar, as it is not in a canonical format")]
    BlsScalarMalformed,
}

/// Reads n bytes from slice and returns the n bytes along with the rest of the slice
pub fn read_n(n: usize, bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if bytes.len() < n {
        return Err(SerialisationErrors::NotEnoughBytes.into());
    }
    let bytes32 = &bytes[0..n];
    let rest = &bytes[n..];
    Ok((bytes32, rest))
}

/// Reads 32 bytes and converts it to a BlsScalar
/// Returns the remaining bytes
pub fn read_scalar(bytes: &[u8]) -> Result<(BlsScalar, &[u8]), Error> {
    let (bytes32, rest) = read_n(32, bytes)?;
    let mut arr32 = [0u8; 32];
    arr32.copy_from_slice(bytes32);
    let scalar = BlsScalar::from_bytes(&arr32);
    if scalar.is_none().into() {
        return Err(SerialisationErrors::BlsScalarMalformed.into());
    }
    Ok((scalar.unwrap(), rest))
}
/// Writes a BlsScalar into a mutable slice
pub fn write_scalar(scalar: &BlsScalar, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&scalar.to_bytes());
}

/// Reads 48 bytes and converts it to a G1Affine
/// Returns the remaining bytes
pub fn read_g1_affine(bytes: &[u8]) -> Result<(G1Affine, &[u8]), Error> {
    let (bytes48, rest) = read_n(48, bytes)?;
    let mut arr48 = [0u8; 48];
    arr48.copy_from_slice(bytes48);
    let g1 = G1Affine::from_compressed(&arr48);
    if g1.is_none().into() {
        return Err(SerialisationErrors::PointMalformed.into());
    }
    Ok((g1.unwrap(), rest))
}
/// Reads 48 bytes and converts it to a Commitment
/// Returns the remaining bytes
pub fn read_commitment(bytes: &[u8]) -> Result<(Commitment, &[u8]), Error> {
    let (g1, rest) = read_g1_affine(bytes)?;
    Ok((Commitment::from_affine(g1), rest))
}
/// Writes a G1Affine into a mutable slice
pub fn write_g1_affine(affine: &G1Affine, bytes: &mut Vec<u8>) {
    let bytes48 = affine.to_compressed();
    bytes.extend_from_slice(&bytes48);
}
/// Writes a Commitment into a mutable slice
pub fn write_commitment(commitment: &Commitment, bytes: &mut Vec<u8>) {
    write_g1_affine(&commitment.0, bytes)
}

/// Reads 96 bytes and converts it to a G2Affine
/// Returns the remaining bytes
pub fn read_g2_affine(bytes: &[u8]) -> Result<(G2Affine, &[u8]), Error> {
    let (bytes96, rest) = read_n(96, bytes)?;
    let mut arr96 = [0u8; 96];
    arr96.copy_from_slice(bytes96);
    let g2 = G2Affine::from_compressed(&arr96);
    if g2.is_none().into() {
        return Err(SerialisationErrors::PointMalformed.into());
    }
    Ok((g2.unwrap(), rest))
}

/// Reads 8 bytes and converts it to a u64
/// Returns the remaining bytes
pub fn read_u64(bytes: &[u8]) -> Result<(u64, &[u8]), Error> {
    let (bytes8, rest) = read_n(8, bytes)?;
    let mut arr8 = [0u8; 8];
    arr8.copy_from_slice(bytes8);
    Ok((u64::from_be_bytes(arr8), rest))
}
/// Writes a u64 into a mutable slice
pub fn write_u64(val: u64, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&u64::to_be_bytes(val));
}

/// Reads the bytes slice and parses a Vector of scalars
/// Returns the remaining bytes
pub fn read_scalars(bytes: &[u8]) -> Result<(Vec<BlsScalar>, &[u8]), Error> {
    let (num_scalars, mut bytes) = read_u64(bytes)?;

    let mut poly_vec = Vec::new();
    for _ in 0..num_scalars {
        let (scalar, rest) = read_scalar(bytes)?;
        poly_vec.push(scalar);
        bytes = rest;
    }
    Ok((poly_vec, bytes))
}
/// Writes a Vector of scalars into a mutable slice
pub fn write_scalars(val: &[BlsScalar], bytes: &mut Vec<u8>) {
    let num_scalars = val.len() as u64;
    write_u64(num_scalars, bytes);

    for scalar in val.iter() {
        write_scalar(scalar, bytes)
    }
}
/// Reads the bytes slice and parses a Polynomial
/// Returns the remaining bytes
pub fn read_polynomial(bytes: &[u8]) -> Result<(Polynomial, &[u8]), Error> {
    let (poly_vec, rest) = read_scalars(bytes)?;
    Ok((Polynomial::from_coefficients_vec(poly_vec), rest))
}
/// Writes a Polynomial into a mutable slice
pub fn write_polynomial(val: &Polynomial, bytes: &mut Vec<u8>) {
    write_scalars(&val.coeffs, bytes);
}
/// Reads the bytes slice and parses an Evaluation struct
/// Returns the remaining bytes
pub fn read_evaluations(
    domain: EvaluationDomain,
    bytes: &[u8],
) -> Result<(Evaluations, &[u8]), Error> {
    let (scalars, rest) = read_scalars(bytes)?;

    let evals = Evaluations::from_vec_and_domain(scalars, domain);

    Ok((evals, rest))
}
/// Writes an Evaluation struct into a mutable slice
pub fn write_evaluations(val: &Evaluations, bytes: &mut Vec<u8>) {
    write_scalars(&val.evals, bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_read_write_scalar() {
        let mut bytes = Vec::new();

        let scalar = BlsScalar::random(&mut rand::thread_rng());

        write_scalar(&scalar, &mut bytes);
        let (got, rest) = read_scalar(&bytes).unwrap();
        assert_eq!(rest.len(), 0);

        assert_eq!(got, scalar);
    }
    #[test]
    fn test_read_write_scalars_polynomial_evaluations() {
        let mut bytes = Vec::new();

        let scalars: Vec<_> = (0..100)
            .map(|_| BlsScalar::random(&mut rand::thread_rng()))
            .collect();

        let polynomial = Polynomial::from_coefficients_slice(&scalars);

        let domain = EvaluationDomain::new(scalars.len()).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(scalars.clone(), domain);

        write_scalars(&scalars, &mut bytes);
        write_polynomial(&polynomial, &mut bytes);
        write_evaluations(&evaluations, &mut bytes);

        let (got_scalars, rest) = read_scalars(&bytes).unwrap();
        let (got_polynomial, rest) = read_polynomial(&rest).unwrap();
        let (got_evaluations, rest) = read_evaluations(domain, &rest).unwrap();
        assert_eq!(rest.len(), 0);

        assert_eq!(got_scalars, scalars);
        assert_eq!(got_polynomial, polynomial);
        assert_eq!(got_evaluations, evaluations);
    }
    #[test]
    fn test_read_write_u64() {
        use rand_core::RngCore;
        let mut bytes = Vec::new();

        let rand_u64s: Vec<_> = (0..100).map(|_| rand::thread_rng().next_u64()).collect();

        for x in rand_u64s.iter() {
            write_u64(*x, &mut bytes);
        }

        let mut remaining: &[u8] = &bytes;
        for x in rand_u64s.iter() {
            let (got, rest) = read_u64(&remaining).unwrap();
            assert_eq!(got, *x);
            remaining = rest;
        }

        assert_eq!(remaining.len(), 0)
    }

    #[test]
    fn test_read_write_point_comm() {
        let mut bytes = Vec::new();

        let comm = Commitment::from_affine(G1Affine::generator());

        write_commitment(&comm, &mut bytes);
        write_g1_affine(&comm.0, &mut bytes);

        let (got_g1_affine, rest) = read_g1_affine(&bytes).unwrap();
        let (got_comm, rest) = read_commitment(&rest).unwrap();
        assert_eq!(rest.len(), 0);

        assert_eq!(got_g1_affine, comm.0);
        assert_eq!(got_comm, comm);
    }
}
