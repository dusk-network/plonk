// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Semantic checks for archived values. bytecheck derives only structural
//! checks, and archived points and scalars hold raw Montgomery limbs.

use bytecheck::CheckBytes;
use dusk_bls12_381::{BlsScalar, G1Affine};
use rkyv::validation::ArchiveContext;
use rkyv::{Archive, Archived, Deserialize, Infallible};

use crate::commitment_scheme::Commitment;
#[cfg(feature = "alloc")]
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use crate::proof_system::widget::ArchivedVerifierKey;
#[cfg(feature = "alloc")]
use crate::proof_system::widget::alloc::ArchivedProverKey;

/// An archived value that is well formed but not a valid value of its type.
#[derive(Debug)]
pub struct InvalidArchive;

impl core::fmt::Display for InvalidArchive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid archived PLONK value")
    }
}

impl core::error::Error for InvalidArchive {}

/// Checks the listed fields of an archived struct, mapping any failure to
/// [`InvalidArchive`].
macro_rules! check_fields {
    ($value:ident, $context:ident, $($field:tt),+ $(,)?) => {$(
        unsafe {
            bytecheck::CheckBytes::check_bytes(
                core::ptr::addr_of!((*$value).$field),
                $context,
            )
        }
        .map_err(|_| $crate::archive::InvalidArchive)?;
    )+};
}
pub(crate) use check_fields;

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
pub(crate) fn scalars_are_canonical(scalars: &[Archived<BlsScalar>]) -> bool {
    #[cfg(feature = "std")]
    {
        use rayon::prelude::*;

        scalars.par_iter().all(scalar_is_canonical)
    }
    #[cfg(not(feature = "std"))]
    scalars.iter().all(scalar_is_canonical)
}

/// Whether two archived scalar slices hold the same values.
pub(crate) fn same_scalars(
    a: &[Archived<BlsScalar>],
    b: &[Archived<BlsScalar>],
) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| unarchive::<BlsScalar>(a) == unarchive(b))
}

// The byte encoding stores each shared selector once, so archived copies must
// agree.
impl<C: ?Sized> CheckBytes<C> for ArchivedVerifierKey {
    type Error = InvalidArchive;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        check_fields!(
            value,
            context,
            arithmetic,
            logic,
            range,
            fixed_base,
            variable_base,
            permutation,
        );
        let key = unsafe { &*value };
        let same = |a, b| unarchive::<Commitment>(a) == unarchive(b);
        if same(&key.logic.q_c, &key.arithmetic.q_c)
            && same(&key.fixed_base.q_l, &key.arithmetic.q_l)
            && same(&key.fixed_base.q_r, &key.arithmetic.q_r)
        {
            Ok(key)
        } else {
            Err(InvalidArchive)
        }
    }
}

#[cfg(feature = "alloc")]
impl<C> CheckBytes<C> for ArchivedProverKey
where
    C: ArchiveContext + ?Sized,
    C::Error: bytecheck::Error,
{
    type Error = InvalidArchive;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        check_fields!(
            value,
            context,
            arithmetic,
            logic,
            range,
            fixed_base,
            variable_base,
            permutation,
            v_h_coset_8n,
        );
        let key = unsafe { &*value };
        if prover_key_is_valid(key) {
            Ok(key)
        } else {
            Err(InvalidArchive)
        }
    }
}

/// Applies the key-level checks of `ProverKey::from_slice`. Each polynomial
/// and evaluation set has already passed its own checks.
#[cfg(feature = "alloc")]
fn prover_key_is_valid(key: &ArchivedProverKey) -> bool {
    let n = unarchive::<usize>(&key.n);
    let Some(domain) = n
        .checked_mul(8)
        .filter(|size| size.is_power_of_two())
        .and_then(|size| EvaluationDomain::new(size).ok())
    else {
        return false;
    };

    type Pair = Archived<(Polynomial, Evaluations)>;
    let (arithmetic, fixed_base, permutation) =
        (&key.arithmetic, &key.fixed_base, &key.permutation);
    // Evaluation sets carry the canonical domain of their length.
    let fits = |pair: &Pair| {
        pair.0.coeffs().len() <= n && pair.1.evals.len() == domain.size()
    };
    let same = |a: &Pair, b: &Pair| {
        same_scalars(a.0.coeffs(), b.0.coeffs())
            && same_scalars(&a.1.evals, &b.1.evals)
    };

    [
        &arithmetic.q_m,
        &arithmetic.q_l,
        &arithmetic.q_r,
        &arithmetic.q_o,
        &arithmetic.q_f,
        &arithmetic.q_c,
        &arithmetic.q_arith,
        &key.logic.q_logic,
        &key.range.q_range,
        &fixed_base.q_fixed_group_add,
        &key.variable_base.q_variable_group_add,
        &permutation.s_sigma_1,
        &permutation.s_sigma_2,
        &permutation.s_sigma_3,
        &permutation.s_sigma_4,
    ]
    .into_iter()
    .all(fits)
        // The byte encoding stores each shared selector once.
        && same(&key.logic.q_c, &arithmetic.q_c)
        && same(&fixed_base.q_l, &arithmetic.q_l)
        && same(&fixed_base.q_r, &arithmetic.q_r)
        && same(&fixed_base.q_c, &arithmetic.q_c)
        && domain.matches_linear_poly_over_coset(
            permutation.linear_evaluations.evals.iter().map(unarchive),
        )
        && domain.matches_vanishing_poly_over_coset(
            n as u64,
            key.v_h_coset_8n.evals.iter().map(unarchive),
        )
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
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
        >,
    {
        rkyv::check_archived_root::<T>(bytes).is_ok()
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
        assert_eq!(rkyv::from_bytes::<Proof>(&bytes).unwrap(), proof);

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
    fn archived_verifier_keys_share_selectors() {
        let (prover, _) = compiled();
        let key = prover.verifier_key;
        let bytes = archive(&key);
        assert_eq!(rkyv::from_bytes::<VerifierKey>(&bytes).unwrap(), key);

        let logic_q_c = offset::<VerifierKey>(&bytes, |k| {
            core::ptr::addr_of!(k.logic.q_c).cast()
        });
        let mut bytes = bytes;
        bytes[logic_q_c..logic_q_c + G1Affine::RAW_SIZE]
            .copy_from_slice(&key.arithmetic.q_m.0.to_raw_bytes());
        assert!(!checks::<VerifierKey>(&bytes));
    }

    #[test]
    fn archived_prover_keys_match_their_decoder() {
        let (prover, _) = compiled();
        let key = prover.prover_key;
        let bytes = archive(&key);
        assert_eq!(rkyv::from_bytes::<ProverKey>(&bytes).unwrap(), key);

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

        // Halving the size leaves polynomials over degree and evaluations
        // off the domain.
        let n = key.n;
        assert!(!mutated(|k| core::ptr::addr_of!(k.n).cast(), &|bytes| {
            bytes[..4].copy_from_slice(&(n as u32 / 2).to_le_bytes())
        }));
        // An unreduced coefficient.
        assert!(!mutated(
            |k| k.arithmetic.q_m.0.coeffs().as_ptr().cast(),
            &|bytes| add_modulus(&mut bytes[..32], &R),
        ));
        // A leading zero coefficient.
        assert!(!mutated(
            |k| k.arithmetic.q_m.0.coeffs().last().unwrap() as *const _ as _,
            &replace(BlsScalar::zero()),
        ));
        // Shared selectors that disagree.
        assert!(!mutated(|k| k.fixed_base.q_c.1.evals.as_ptr().cast(), &two));
        // Cached evaluations that disagree with the domain.
        assert!(!mutated(
            |k| k.permutation.linear_evaluations.evals.as_ptr().cast(),
            &two,
        ));
        assert!(!mutated(|k| k.v_h_coset_8n.evals.as_ptr().cast(), &two));
    }
}
