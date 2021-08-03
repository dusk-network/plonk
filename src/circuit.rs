// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Tools & traits for PLONK circuits

use crate::commitment_scheme::kzg10::PublicParameters;
use crate::constraint_system::StandardComposer;
use crate::error::Error;
use crate::proof_system::{Proof, Prover, ProverKey, Verifier, VerifierKey};
use alloc::vec::Vec;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable, Write};
use dusk_jubjub::{JubJubAffine, JubJubScalar};

#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "canon", derive(Canon))]
/// Structure that represents a PLONK Circuit Public Input converted into it's
/// &\[[`BlsScalar`]\] repr.
pub struct PublicInputValue(pub(crate) Vec<BlsScalar>);

impl From<BlsScalar> for PublicInputValue {
    fn from(scalar: BlsScalar) -> Self {
        Self(vec![scalar])
    }
}

impl From<JubJubScalar> for PublicInputValue {
    fn from(scalar: JubJubScalar) -> Self {
        Self(vec![scalar.into()])
    }
}

impl From<JubJubAffine> for PublicInputValue {
    fn from(point: JubJubAffine) -> Self {
        Self(vec![point.get_x(), point.get_y()])
    }
}

#[derive(Debug, Clone)]
/// Collection of structs/objects that the Verifier will use in order to
/// de/serialize data needed for Circuit proof verification.
/// This structure can be seen as a link between the [`Circuit`] public input
/// positions and the [`VerifierKey`] that the Verifier needs to use.
pub struct VerifierData {
    key: VerifierKey,
    pi_pos: Vec<usize>,
}

impl VerifierData {
    /// Creates a new `VerifierData` from a [`VerifierKey`] and the public
    /// input positions of the circuit that it represents.
    pub const fn new(key: VerifierKey, pi_pos: Vec<usize>) -> Self {
        Self { key, pi_pos }
    }

    /// Returns a reference to the contained [`VerifierKey`].
    pub const fn key(&self) -> &VerifierKey {
        &self.key
    }

    /// Returns a reference to the contained Public Input positions.
    pub const fn pi_pos(&self) -> &Vec<usize> {
        &self.pi_pos
    }

    /// Deserializes the `VerifierData` into a vector of bytes.
    #[allow(unused_must_use)]
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut buff =
            vec![
                0u8;
                VerifierKey::SIZE + u32::SIZE + self.pi_pos.len() * u32::SIZE
            ];
        let mut writer = &mut buff[..];

        writer.write(&self.key.to_bytes());
        writer.write(&(self.pi_pos.len() as u32).to_bytes());
        self.pi_pos.iter().copied().for_each(|pos| {
            // Omit the result since disk_bytes write can't fail here
            // due to the fact that we're writing into a vector basically.
            let _ = writer.write(&(pos as u32).to_bytes());
        });

        buff
    }

    /// Serializes `VerifierData` from a slice of bytes.
    pub fn from_slice(mut buf: &[u8]) -> Result<Self, Error> {
        let key = VerifierKey::from_reader(&mut buf)?;
        let pos_num = u32::from_reader(&mut buf)? as usize;

        let mut pi_pos = vec![];
        for _ in 0..pos_num {
            pi_pos.push(u32::from_reader(&mut buf)? as usize);
        }

        Ok(Self { key, pi_pos })
    }
}

/// Trait that should be implemented for any circuit function to provide to it
/// the capabilities of automatically being able to generate, and verify proofs
/// as well as compile the circuit.
/// # Example
///
/// ```
/// use dusk_plonk::prelude::*;
/// use dusk_plonk::constraint_system::ecc::scalar_mul;
/// use rand_core::OsRng;
///
/// fn main() -> Result<(), Error> {
/// // Implements a circuit that checks:
/// // 1) a + b = c where C is a PI
/// // 2) a <= 2^6
/// // 3) b <= 2^5
/// // 4) a * b = d where D is a PI
/// // 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a PI
/// #[derive(Debug, Default)]
/// pub struct TestCircuit {
///     a: BlsScalar,
///     b: BlsScalar,
///     c: BlsScalar,
///     d: BlsScalar,
///     e: JubJubScalar,
///     f: JubJubAffine,
/// }
///
/// impl Circuit for TestCircuit {
///     const CIRCUIT_ID: [u8; 32] = [0xff; 32];
///     fn gadget(
///         &mut self,
///         composer: &mut StandardComposer,
///     ) -> Result<(), Error> {
///         // Add fixed witness zero
///         let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());
///         let a = composer.add_input(self.a);
///         let b = composer.add_input(self.b);
///         // Make first constraint a + b = c
///         composer.poly_gate(
///             a,
///             b,
///             zero,
///             BlsScalar::zero(),
///             BlsScalar::one(),
///             BlsScalar::one(),
///             BlsScalar::zero(),
///             BlsScalar::zero(),
///             Some(-self.c),
///         );
///         // Check that a and b are in range
///         composer.range_gate(a, 1 << 6);
///         composer.range_gate(b, 1 << 5);
///         // Make second constraint a * b = d
///         composer.poly_gate(
///             a,
///             b,
///             zero,
///             BlsScalar::one(),
///             BlsScalar::zero(),
///             BlsScalar::zero(),
///             BlsScalar::one(),
///             BlsScalar::zero(),
///             Some(-self.d),
///         );
///
///         let e = composer.add_input(self.e.into());
///         let scalar_mul_result =
///             composer.fixed_base_scalar_mul(
///                 e, dusk_jubjub::GENERATOR_EXTENDED,
///             );
///         // Apply the constrain
///         composer
///             .assert_equal_public_point(scalar_mul_result, self.f);
///         Ok(())
///     }
///     fn padded_circuit_size(&self) -> usize {
///         1 << 11
///     }
/// }
///
/// let pp = PublicParameters::setup(1 << 12, &mut OsRng)?;
/// // Initialize the circuit
/// let mut circuit = TestCircuit::default();
/// // Compile the circuit
/// let (pk, vd) = circuit.compile(&pp)?;
///
/// // Prover POV
/// let proof = {
///     let mut circuit = TestCircuit {
///         a: BlsScalar::from(20u64),
///         b: BlsScalar::from(5u64),
///         c: BlsScalar::from(25u64),
///         d: BlsScalar::from(100u64),
///         e: JubJubScalar::from(2u64),
///         f: JubJubAffine::from(
///             dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(2u64),
///         ),
///     };
///
///     circuit.gen_proof(&pp, &pk, b"Test")
/// }?;
///
/// // Verifier POV
/// let public_inputs: Vec<PublicInputValue> = vec![
///     BlsScalar::from(25u64).into(),
///     BlsScalar::from(100u64).into(),
///     JubJubAffine::from(
///         dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(2u64),
///     )
///     .into(),
/// ];
///
/// circuit::verify_proof(
///     &pp,
///     &vd.key(),
///     &proof,
///     &public_inputs,
///     &vd.pi_pos(),
///     b"Test",
/// )
/// }
pub trait Circuit
where
    Self: Sized,
{
    /// Circuit identifier associated constant.
    const CIRCUIT_ID: [u8; 32];
    /// Gadget implementation used to fill the composer.
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error>;
    /// Compiles the circuit by using a function that returns a `Result`
    /// with the `ProverKey`, `VerifierKey` and the circuit size.
    fn compile(
        &mut self,
        pub_params: &PublicParameters,
    ) -> Result<(ProverKey, VerifierData), Error> {
        // Setup PublicParams
        let (ck, _) = pub_params.trim(self.padded_circuit_size())?;
        // Generate & save `ProverKey` with some random values.
        let mut prover = Prover::new(b"CircuitCompilation");
        self.gadget(prover.mut_cs())?;
        let pi_pos = prover.mut_cs().pi_positions();
        prover.preprocess(&ck)?;

        // Generate & save `VerifierKey` with some random values.
        let mut verifier = Verifier::new(b"CircuitCompilation");
        self.gadget(verifier.mut_cs())?;
        verifier.preprocess(&ck)?;
        Ok((
            prover
                .prover_key
                .expect("Unexpected error. Missing ProverKey in compilation"),
            VerifierData::new(
                verifier.verifier_key.expect(
                    "Unexpected error. Missing VerifierKey in compilation",
                ),
                pi_pos,
            ),
        ))
    }

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey`
    /// instances.
    fn gen_proof(
        &mut self,
        pub_params: &PublicParameters,
        prover_key: &ProverKey,
        transcript_init: &'static [u8],
    ) -> Result<Proof, Error> {
        let (ck, _) = pub_params.trim(self.padded_circuit_size())?;
        // New Prover instance
        let mut prover = Prover::new(transcript_init);
        // Fill witnesses for Prover
        self.gadget(prover.mut_cs())?;
        // Add ProverKey to Prover
        prover.prover_key = Some(prover_key.clone());
        prover.prove(&ck)
    }

    /// Returns the Circuit size padded to the next power of two.
    fn padded_circuit_size(&self) -> usize;
}

/// Verifies a proof using the provided `CircuitInputs` & `VerifierKey`
/// instances.
pub fn verify_proof(
    pub_params: &PublicParameters,
    verifier_key: &VerifierKey,
    proof: &Proof,
    pub_inputs_values: &[PublicInputValue],
    pub_inputs_positions: &[usize],
    transcript_init: &'static [u8],
) -> Result<(), Error> {
    let mut verifier = Verifier::new(transcript_init);
    verifier.verifier_key = Some(verifier_key.clone());
    verifier.verify(
        proof,
        pub_params.opening_key(),
        build_pi(
            pub_inputs_values,
            pub_inputs_positions,
            verifier_key.padded_circuit_size(),
        )
        .as_slice(),
    )
}

/// Build PI vector for Proof verifications.
fn build_pi(
    pub_input_values: &[PublicInputValue],
    pub_input_pos: &[usize],
    trim_size: usize,
) -> Vec<BlsScalar> {
    let mut pi = vec![BlsScalar::zero(); trim_size];
    pub_input_values
        .iter()
        .map(|pub_input| pub_input.0.clone())
        .flatten()
        .zip(pub_input_pos.iter().copied())
        .for_each(|(value, pos)| {
            pi[pos] = -value;
        });
    pi
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::StandardComposer;
    use crate::proof_system::ProverKey;

    // Implements a circuit that checks:
    // 1) a + b = c where C is a PI
    // 2) a <= 2^6
    // 3) b <= 2^5
    // 4) a * b = d where D is a PI
    // 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a PI
    #[derive(Debug, Default)]
    pub struct TestCircuit {
        a: BlsScalar,
        b: BlsScalar,
        c: BlsScalar,
        d: BlsScalar,
        e: JubJubScalar,
        f: JubJubAffine,
    }

    impl Circuit for TestCircuit {
        const CIRCUIT_ID: [u8; 32] = [0xff; 32];
        fn gadget(
            &mut self,
            composer: &mut StandardComposer,
        ) -> Result<(), Error> {
            let a = composer.add_input(self.a);
            let b = composer.add_input(self.b);
            // Make first constraint a + b = c
            composer.poly_gate(
                a,
                b,
                composer.zero_var,
                BlsScalar::zero(),
                BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
                Some(-self.c),
            );
            // Check that a and b are in range
            composer.range_gate(a, 1 << 6);
            composer.range_gate(b, 1 << 5);
            // Make second constraint a * b = d
            composer.poly_gate(
                a,
                b,
                composer.zero_var,
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
                BlsScalar::one(),
                BlsScalar::zero(),
                Some(-self.d),
            );

            let e = composer.add_input(self.e.into());
            let scalar_mul_result = composer
                .fixed_base_scalar_mul(e, dusk_jubjub::GENERATOR_EXTENDED);
            // Apply the constrain
            composer.assert_equal_public_point(scalar_mul_result, self.f);
            Ok(())
        }
        fn padded_circuit_size(&self) -> usize {
            1 << 11
        }
    }

    #[test]
    fn test_full() -> Result<(), Error> {
        use rand_core::OsRng;
        use std::fs::{self, File};
        use std::io::Write;
        use tempdir::TempDir;

        let tmp = TempDir::new("plonk-keys-test-full")
            .expect("IO error")
            .into_path();
        let pp_path = tmp.clone().join("pp_testcirc");
        let pk_path = tmp.clone().join("pk_testcirc");
        let vd_path = tmp.clone().join("vd_testcirc");

        // Generate CRS
        let pp_p = PublicParameters::setup(1 << 12, &mut OsRng)?;
        File::create(&pp_path)
            .and_then(|mut f| f.write(pp_p.to_raw_var_bytes().as_slice()))
            .expect("IO error");

        // Read PublicParameters
        let pp = fs::read(pp_path).expect("IO error");
        let pp =
            unsafe { PublicParameters::from_slice_unchecked(pp.as_slice()) };

        // Initialize the circuit
        let mut circuit = TestCircuit::default();

        // Compile the circuit
        let (pk_p, og_verifier_data) = circuit.compile(&pp)?;

        // Write the keys
        File::create(&pk_path)
            .and_then(|mut f| f.write(pk_p.to_var_bytes().as_slice()))
            .expect("IO error");

        // Read ProverKey
        let pk = fs::read(pk_path).expect("IO error");
        let pk = ProverKey::from_slice(pk.as_slice())?;

        assert_eq!(pk, pk_p);

        // Store the VerifierData just for the verifier side:
        // (You could also store pi_pos and VerifierKey sepparatedly).
        File::create(&vd_path)
            .and_then(|mut f| {
                f.write(og_verifier_data.to_var_bytes().as_slice())
            })
            .expect("IO error");
        let vd = fs::read(vd_path).expect("IO error");
        let verif_data = VerifierData::from_slice(vd.as_slice())?;
        assert_eq!(og_verifier_data.key(), verif_data.key());
        assert_eq!(og_verifier_data.pi_pos(), verif_data.pi_pos());

        // Prover POV
        let proof = {
            let mut circuit = TestCircuit {
                a: BlsScalar::from(20u64),
                b: BlsScalar::from(5u64),
                c: BlsScalar::from(25u64),
                d: BlsScalar::from(100u64),
                e: JubJubScalar::from(2u64),
                f: JubJubAffine::from(
                    dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(2u64),
                ),
            };

            circuit.gen_proof(&pp, &pk, b"Test")
        }?;

        // Verifier POV
        let public_inputs: Vec<PublicInputValue> = vec![
            BlsScalar::from(25u64).into(),
            BlsScalar::from(100u64).into(),
            JubJubAffine::from(
                dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(2u64),
            )
            .into(),
        ];

        verify_proof(
            &pp,
            &verif_data.key(),
            &proof,
            &public_inputs,
            &verif_data.pi_pos(),
            b"Test",
        )
    }
}
