// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Checked RKYV deserialization of PLONK values.
//!
//! Archive byte checking does not establish all PLONK invariants. Use
//! [`from_bytes`] to validate point and scalar representations, domains,
//! polynomials and key invariants before obtaining a usable value. Archive
//! layouts and serialization are unchanged. Deserialization requires a fallible
//! context whose error can represent [`InvalidArchive`]; `rkyv::Infallible` and
//! `rkyv::from_bytes` cannot perform these checks. Custom contexts can
//! implement `From<InvalidArchive>` for their error, or use [`Deserializer`].

use bytecheck::CheckBytes;
use dusk_bls12_381::BlsScalar;
use rkyv::{Archive, Archived, Deserialize, Infallible};

#[cfg(feature = "alloc")]
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
#[cfg(feature = "alloc")]
use crate::proof_system::widget::alloc::{ArchivedProverKey, ProverKey};
#[cfg(feature = "alloc")]
use crate::proof_system::widget::prover_key_pairs;
#[cfg(feature = "alloc")]
use crate::proof_system::widget::{ArchivedVerifierKey, VerifierKey};

/// An archive that is structurally malformed or violates PLONK invariants.
#[derive(Debug)]
pub struct InvalidArchive;

impl core::fmt::Display for InvalidArchive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid archived PLONK value")
    }
}

impl core::error::Error for InvalidArchive {}

/// A fallible RKYV deserializer that preserves semantic validation errors.
#[derive(Default)]
pub struct Deserializer;

impl rkyv::Fallible for Deserializer {
    type Error = InvalidArchive;
}

/// Structurally checks an archive and deserializes it with semantic validation.
///
/// Generic RKYV callers can instead check the archive with
/// `rkyv::check_archived_root` and deserialize using [`Deserializer`] or a
/// context whose error implements `From<InvalidArchive>`.
pub fn from_bytes<'a, T>(bytes: &'a [u8]) -> Result<T, InvalidArchive>
where
    T: Archive,
    Archived<T>: 'a
        + CheckBytes<rkyv::validation::validators::DefaultValidator<'a>>
        + Deserialize<T, Deserializer>,
{
    rkyv::check_archived_root::<T>(bytes)
        .map_err(|_| InvalidArchive)?
        .deserialize(&mut Deserializer)
}

/// Copies a structurally checked archived value.
pub(crate) fn unarchive<T>(archived: &Archived<T>) -> T
where
    T: Archive,
    Archived<T>: Deserialize<T, Infallible>,
{
    match archived.deserialize(&mut Infallible) {
        Ok(value) => value,
        Err(never) => match never {},
    }
}

/// Whether `scalar` holds canonical limbs, below the modulus.
pub(crate) fn scalar_is_canonical(scalar: &Archived<BlsScalar>) -> bool {
    let scalar: BlsScalar = unarchive(scalar);
    // Adding zero subtracts the modulus from limbs at or above it.
    (scalar + BlsScalar::zero()).internal_repr() == scalar.internal_repr()
}

/// Whether all `scalars` are canonical.
#[cfg(feature = "alloc")]
pub(crate) fn scalars_are_canonical(scalars: &[Archived<BlsScalar>]) -> bool {
    crate::util::all_parallel(scalars, scalar_is_canonical)
}

// The byte encoding stores each shared selector once, so archived copies must
// agree as well.
#[cfg(feature = "alloc")]
impl<D> Deserialize<VerifierKey, D> for ArchivedVerifierKey
where
    D: rkyv::Fallible + ?Sized,
    D::Error: From<InvalidArchive>,
{
    fn deserialize(
        &self,
        deserializer: &mut D,
    ) -> Result<VerifierKey, D::Error> {
        let key = VerifierKey {
            n: self.n.deserialize(deserializer)?,
            arithmetic: self.arithmetic.deserialize(deserializer)?,
            logic: self.logic.deserialize(deserializer)?,
            range: self.range.deserialize(deserializer)?,
            fixed_base: self.fixed_base.deserialize(deserializer)?,
            variable_base: self.variable_base.deserialize(deserializer)?,
            permutation: self.permutation.deserialize(deserializer)?,
        };
        if key.logic.q_c != key.arithmetic.q_c
            || key.fixed_base.q_l != key.arithmetic.q_l
            || key.fixed_base.q_r != key.arithmetic.q_r
        {
            return Err(InvalidArchive.into());
        }
        Ok(key)
    }
}

#[cfg(feature = "alloc")]
impl<D> Deserialize<ProverKey, D> for ArchivedProverKey
where
    D: rkyv::Fallible + ?Sized,
    D::Error: From<InvalidArchive>,
{
    fn deserialize(&self, deserializer: &mut D) -> Result<ProverKey, D::Error> {
        let key = ProverKey {
            n: self.n.deserialize(deserializer)?,
            arithmetic: self.arithmetic.deserialize(deserializer)?,
            logic: self.logic.deserialize(deserializer)?,
            range: self.range.deserialize(deserializer)?,
            fixed_base: self.fixed_base.deserialize(deserializer)?,
            variable_base: self.variable_base.deserialize(deserializer)?,
            permutation: self.permutation.deserialize(deserializer)?,
            v_h_coset_8n: self.v_h_coset_8n.deserialize(deserializer)?,
        };
        if !prover_key_is_valid(&key) {
            return Err(InvalidArchive.into());
        }
        Ok(key)
    }
}

/// Applies the key-level checks of `ProverKey::from_slice`. Each polynomial
/// and evaluation set has already passed its own checks.
#[cfg(feature = "alloc")]
fn prover_key_is_valid(key: &ProverKey) -> bool {
    let n = key.n;
    let Some(domain) = n
        .checked_mul(8)
        .filter(|size| size.is_power_of_two())
        .and_then(|size| EvaluationDomain::new(size).ok())
    else {
        return false;
    };

    type Pair = (Polynomial, Evaluations);
    let (arithmetic, fixed_base, permutation) =
        (&key.arithmetic, &key.fixed_base, &key.permutation);
    // Each polynomial fits the circuit and its cached coset evaluations,
    // which also fixes their domain.
    let fits = |pair: &Pair| {
        pair.0.len() <= n
            && domain.matches_coset_evaluations(
                &pair.0,
                pair.1.evals.iter().copied(),
            )
    };

    crate::util::all_parallel(&prover_key_pairs!(key, &), |pair| fits(pair))
        && key.logic.q_c == arithmetic.q_c
        && fixed_base.q_l == arithmetic.q_l
        && fixed_base.q_r == arithmetic.q_r
        && fixed_base.q_c == arithmetic.q_c
        && domain.matches_linear_poly_over_coset(
            permutation.linear_evaluations.evals.iter().copied(),
        )
        && domain.matches_vanishing_poly_over_coset(
            n as u64,
            key.v_h_coset_8n.evals.iter().copied(),
        )
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use dusk_bls12_381::G1Affine;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rkyv::AlignedVec;

    use super::*;
    use crate::prelude::*;
    use crate::proof_system::proof::ArchivedProof;
    use crate::proof_system::{ProverKey, VerifierKey};

    #[derive(Default)]
    struct TestCircuit;

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let a = composer.append_witness(BlsScalar::from(3));
            let b = composer.append_witness(BlsScalar::from(5));
            let c = composer.gate_mul(Constraint::new().mult(1).a(a).b(b));
            // Sets q_l and q_r, which keys store more than once.
            composer.gate_add(Constraint::new().left(1).right(1).a(a).b(b));
            composer.assert_equal_constant(c, BlsScalar::from(15), None);
            composer.component_range_bits::<8>(a);
            Ok(())
        }
    }

    const P: [u64; 6] = [
        0xb9fe_ffff_ffff_aaab,
        0x1eab_fffe_b153_ffff,
        0x6730_d2a0_f6b0_f624,
        0x6477_4b84_f385_12bf,
        0x4b1b_a7b6_434b_acd7,
        0x1a01_11ea_397f_e69a,
    ];
    const R: [u64; 4] = [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];

    /// Adds `modulus` to little-endian limbs: the same value, non-canonical.
    fn add_modulus(bytes: &mut [u8], modulus: &[u64]) {
        let mut carry = 0;
        for (limb, m) in bytes.chunks_mut(8).zip(modulus) {
            let value = u64::from_le_bytes(limb.try_into().unwrap()) as u128
                + *m as u128
                + carry;
            limb.copy_from_slice(&(value as u64).to_le_bytes());
            carry = value >> 64;
        }
    }

    fn archive<T>(value: &T) -> AlignedVec
    where
        T: rkyv::Serialize<rkyv::ser::serializers::AllocSerializer<256>>,
    {
        rkyv::to_bytes::<_, 256>(value).unwrap()
    }

    /// Returns the offset of the archived field `at` selects.
    fn offset<T: Archive>(
        bytes: &AlignedVec,
        at: impl FnOnce(&Archived<T>) -> *const u8,
    ) -> usize {
        at(unsafe { rkyv::archived_root::<T>(bytes) }) as usize
            - bytes.as_ptr() as usize
    }

    fn checks<T: Archive>(bytes: &[u8]) -> bool
    where
        Archived<T>: for<'a> CheckBytes<
                rkyv::validation::validators::DefaultValidator<'a>,
            > + Deserialize<T, Deserializer>,
    {
        from_bytes::<T>(bytes).is_ok()
    }

    fn compiled() -> (Prover, Proof) {
        let mut rng = StdRng::seed_from_u64(981);
        let pp = PublicParameters::setup(1 << 6, &mut rng).unwrap();
        let (prover, _) =
            Compiler::compile::<TestCircuit>(&pp, b"archive").unwrap();
        let (proof, _) = prover.prove(&mut rng, &TestCircuit).unwrap();
        (prover, proof)
    }

    #[test]
    fn archived_proofs_reject_invalid_elements() {
        let (_, proof) = compiled();
        let bytes = archive(&proof);
        assert_eq!(from_bytes::<Proof>(&bytes).unwrap(), proof);

        let a_comm = offset::<Proof>(&bytes, |p: &ArchivedProof| {
            core::ptr::addr_of!(p.a_comm).cast()
        });
        let point = proof.a_comm.0.to_raw_bytes();
        let outside_subgroup = (1u8..)
            .filter_map(|x| {
                let mut compressed = [0u8; 48];
                compressed[0] = 0x80;
                compressed[47] = x;
                Option::<G1Affine>::from(G1Affine::from_compressed_unchecked(
                    &compressed,
                ))
            })
            .find(|p| !bool::from(p.is_torsion_free()))
            .unwrap()
            .to_raw_bytes();
        let identity = G1Affine::identity().to_raw_bytes();

        let mut unreduced = point;
        add_modulus(&mut unreduced[..48], &P);
        let mut off_curve = point;
        off_curve[48] ^= 1;
        let mut flag = identity;
        flag[96] = 2;
        let mut identity_coordinates = identity;
        identity_coordinates[0] = 1;

        for raw in [
            unreduced,
            off_curve,
            outside_subgroup,
            flag,
            identity_coordinates,
        ] {
            let mut bytes = bytes.clone();
            bytes[a_comm..a_comm + G1Affine::RAW_SIZE].copy_from_slice(&raw);
            assert!(!checks::<Proof>(&bytes));
        }

        let a_eval = offset::<Proof>(&bytes, |p: &ArchivedProof| {
            core::ptr::addr_of!(p.evaluations.a_eval).cast()
        });
        let mut unreduced = bytes.clone();
        add_modulus(&mut unreduced[a_eval..a_eval + 32], &R);
        assert!(!checks::<Proof>(&unreduced));
    }

    #[test]
    fn nested_archives_preserve_semantic_validation() {
        #[derive(Archive, rkyv::Serialize, Deserialize)]
        #[archive(bound(deserialize = "__D::Error: From<InvalidArchive>"))]
        #[archive_attr(derive(CheckBytes))]
        struct WrappedProof {
            proof: Proof,
        }

        let (_, proof) = compiled();
        let mut bytes = archive(&WrappedProof {
            proof: proof.clone(),
        });
        assert_eq!(from_bytes::<WrappedProof>(&bytes).unwrap().proof, proof);

        let at = offset::<WrappedProof>(&bytes, |wrapped| {
            core::ptr::addr_of!(wrapped.proof.a_comm).cast()
        });
        let mut off_curve = G1Affine::identity().to_raw_bytes();
        off_curve[G1Affine::RAW_SIZE - 1] = 0;
        bytes[at..at + G1Affine::RAW_SIZE].copy_from_slice(&off_curve);
        // Structure remains valid; deserialization must still reject an
        // off-curve point inside a downstream archive.
        assert!(rkyv::check_archived_root::<WrappedProof>(&bytes).is_ok());
        assert!(from_bytes::<WrappedProof>(&bytes).is_err());
    }

    #[test]
    fn archived_verifier_keys_share_selectors() {
        let (prover, _) = compiled();
        let key = prover.verifier_key;
        let bytes = archive(&key);
        assert_eq!(from_bytes::<VerifierKey>(&bytes).unwrap(), key);

        let copies: [fn(&Archived<VerifierKey>) -> *const u8; 3] = [
            |k| core::ptr::addr_of!(k.logic.q_c).cast(),
            |k| core::ptr::addr_of!(k.fixed_base.q_l).cast(),
            |k| core::ptr::addr_of!(k.fixed_base.q_r).cast(),
        ];
        for copy in copies {
            let mut bytes = bytes.clone();
            let at = offset::<VerifierKey>(&bytes, copy);
            bytes[at..at + G1Affine::RAW_SIZE]
                .copy_from_slice(&key.arithmetic.q_m.0.to_raw_bytes());
            assert!(!checks::<VerifierKey>(&bytes));
        }
    }

    #[test]
    fn prover_keys_reject_polynomials_over_degree() {
        let (prover, _) = compiled();
        let mut key = prover.prover_key;
        // One coefficient too many, with matching coset evaluations.
        let domain = key.arithmetic.q_m.1.domain();
        let poly = Polynomial::from_coefficients_vec(vec![
            BlsScalar::one();
            key.n + 1
        ]);
        let evals =
            Evaluations::from_vec_and_domain(domain.coset_fft(&poly), domain);
        key.arithmetic.q_m = (poly, evals);

        assert!(!checks::<ProverKey>(&archive(&key)));
        assert!(ProverKey::from_slice(&key.to_var_bytes()).is_err());
    }

    #[test]
    fn archived_prover_keys_need_a_power_of_two_size() {
        // Every pair holds the constant one, which fits any `n`, so only the
        // size rule separates the two keys.
        let archive_for = |n: usize| {
            let mut key = compiled().0.prover_key;
            let domain = EvaluationDomain::new(8 * n).unwrap();
            let one = Polynomial::from_coefficients_vec(vec![BlsScalar::one()]);
            let evals = domain.coset_fft(&one);
            let pair = (one, Evaluations::from_vec_and_domain(evals, domain));
            for slot in prover_key_pairs!(key, &mut) {
                *slot = pair.clone();
            }
            for slot in [
                &mut key.logic.q_c,
                &mut key.fixed_base.q_l,
                &mut key.fixed_base.q_r,
                &mut key.fixed_base.q_c,
            ] {
                *slot = pair.clone();
            }
            let linear =
                domain.coset_fft(&[BlsScalar::zero(), BlsScalar::one()]);
            key.permutation.linear_evaluations =
                Evaluations::from_vec_and_domain(linear, domain);
            key.v_h_coset_8n =
                domain.compute_vanishing_poly_over_coset(n as u64);
            key.n = n;
            archive(&key)
        };
        assert!(checks::<ProverKey>(&archive_for(4)));
        // `8 * 3` rounds up to the same size-32 domain.
        assert!(!checks::<ProverKey>(&archive_for(3)));
    }

    #[test]
    fn archived_prover_keys_match_their_decoder() {
        let (prover, _) = compiled();
        let key = prover.prover_key;
        let bytes = archive(&key);
        assert_eq!(from_bytes::<ProverKey>(&bytes).unwrap(), key);

        let mutated = |at: fn(&Archived<ProverKey>) -> *const u8,
                       mutate: &dyn Fn(&mut [u8])| {
            let mut bytes = bytes.clone();
            let at = offset::<ProverKey>(&bytes, at);
            mutate(&mut bytes[at..]);
            checks::<ProverKey>(&bytes)
        };
        let replace = |scalar: BlsScalar| {
            move |bytes: &mut [u8]| {
                for (limb, value) in
                    bytes.chunks_mut(8).zip(scalar.internal_repr())
                {
                    limb.copy_from_slice(&value.to_le_bytes());
                }
            }
        };
        let two = replace(BlsScalar::from(2));

        // Halving the size leaves evaluations off the domain.
        let n = key.n;
        assert!(!mutated(|k| core::ptr::addr_of!(k.n).cast(), &|bytes| {
            bytes[..4].copy_from_slice(&(n as u32 / 2).to_le_bytes())
        }));
        // An unreduced coefficient.
        assert!(!mutated(
            |k| k.arithmetic.q_m.0.coeffs().as_ptr().cast(),
            &|bytes| add_modulus(&mut bytes[..32], &R),
        ));
        type At = fn(&Archived<ProverKey>) -> *const u8;
        // The shared selector copies, each after the evaluations of its
        // arithmetic copy.
        let copies: [(At, At, At); 4] = [
            (
                |k| k.arithmetic.q_c.1.evals.as_ptr().cast(),
                |k| k.logic.q_c.0.coeffs().as_ptr().cast(),
                |k| k.logic.q_c.1.evals.as_ptr().cast(),
            ),
            (
                |k| k.arithmetic.q_l.1.evals.as_ptr().cast(),
                |k| k.fixed_base.q_l.0.coeffs().as_ptr().cast(),
                |k| k.fixed_base.q_l.1.evals.as_ptr().cast(),
            ),
            (
                |k| k.arithmetic.q_r.1.evals.as_ptr().cast(),
                |k| k.fixed_base.q_r.0.coeffs().as_ptr().cast(),
                |k| k.fixed_base.q_r.1.evals.as_ptr().cast(),
            ),
            (
                |k| k.arithmetic.q_c.1.evals.as_ptr().cast(),
                |k| k.fixed_base.q_c.0.coeffs().as_ptr().cast(),
                |k| k.fixed_base.q_c.1.evals.as_ptr().cast(),
            ),
        ];
        // Coset evaluations that no longer match their polynomial, for every
        // selector and sigma. A shared selector changes in each stored copy,
        // so that only the coset check can reject it.
        for i in 0..prover_key_pairs!(key, &).len() {
            let mut bytes = bytes.clone();
            let at = offset::<ProverKey>(&bytes, |k| {
                prover_key_pairs!(k, &)[i].1.evals.as_ptr().cast()
            });
            two(&mut bytes[at..]);
            for &(arithmetic, _, evals) in &copies {
                if offset::<ProverKey>(&bytes, arithmetic) == at {
                    let at = offset::<ProverKey>(&bytes, evals);
                    two(&mut bytes[at..]);
                }
            }
            assert!(!checks::<ProverKey>(&bytes));
        }
        // Shared selector copies that disagree, in coefficients or
        // evaluations.
        assert!(
            [
                &key.arithmetic.q_c,
                &key.arithmetic.q_l,
                &key.arithmetic.q_r
            ]
            .iter()
            .all(|(poly, _)| poly.len() > 1)
        );
        for (_, coeffs, evals) in copies {
            assert!(!mutated(coeffs, &two));
            assert!(!mutated(evals, &two));
        }
        // Cached evaluations that disagree with the domain.
        assert!(!mutated(
            |k| k.permutation.linear_evaluations.evals.as_ptr().cast(),
            &two,
        ));
        assert!(!mutated(|k| k.v_h_coset_8n.evals.as_ptr().cast(), &two));
    }
}
