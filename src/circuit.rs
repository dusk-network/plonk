// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Tools & traits for PLONK circuits

use crate::commitment_scheme::PublicParameters;
use crate::constraint_system::TurboComposer;
use crate::error::Error;
use crate::proof_system::{Proof, Prover, ProverKey, Verifier, VerifierKey};
use alloc::vec::Vec;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable, Write};
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};

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

impl From<JubJubExtended> for PublicInputValue {
    fn from(point: JubJubExtended) -> Self {
        JubJubAffine::from(point).into()
    }
}

#[derive(Debug, Clone)]
/// Collection of structs/objects that the Verifier will use in order to
/// de/serialize data needed for Circuit proof verification.
/// This structure can be seen as a link between the [`Circuit`] public input
/// positions and the [`VerifierKey`] that the Verifier needs to use.
pub struct VerifierData {
    key: VerifierKey,
    public_inputs_indexes: Vec<usize>,
}

impl VerifierData {
    /// Creates a new `VerifierData` from a [`VerifierKey`] and the public
    /// input positions of the circuit that it represents.
    pub const fn new(
        key: VerifierKey,
        public_inputs_indexes: Vec<usize>,
    ) -> Self {
        Self {
            key,
            public_inputs_indexes,
        }
    }

    /// Returns a reference to the contained [`VerifierKey`].
    pub const fn key(&self) -> &VerifierKey {
        &self.key
    }

    /// Returns a reference to the contained Public Input positions.
    pub fn public_inputs_indexes(&self) -> &[usize] {
        &self.public_inputs_indexes
    }

    /// Deserializes the `VerifierData` into a vector of bytes.
    #[allow(unused_must_use)]
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut buff = vec![
            0u8;
            VerifierKey::SIZE
                + u32::SIZE
                + self.public_inputs_indexes.len() * u32::SIZE
        ];
        let mut writer = &mut buff[..];

        writer.write(&self.key.to_bytes());
        writer.write(&(self.public_inputs_indexes.len() as u32).to_bytes());
        self.public_inputs_indexes.iter().copied().for_each(|pos| {
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

        let mut public_inputs_indexes = vec![];
        for _ in 0..pos_num {
            public_inputs_indexes.push(u32::from_reader(&mut buf)? as usize);
        }

        Ok(Self {
            key,
            public_inputs_indexes,
        })
    }
}

/// Trait that should be implemented for any circuit function to provide to it
/// the capabilities of automatically being able to generate, and verify proofs
/// as well as compile/preprocess the circuit.
/// # Example
///
/// ```
/// use dusk_plonk::prelude::*;
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
///         composer: &mut TurboComposer,
///     ) -> Result<(), Error> {
///         // Add fixed witness zero
///         let zero = TurboComposer::constant_zero();
///         let a = composer.append_witness(self.a);
///         let b = composer.append_witness(self.b);
///
///         // Make first constraint a + b = c
///         let constraint = Constraint::new()
///             .left(1)
///             .right(1)
///             .public(-self.c)
///             .a(a)
///             .b(b);
///
///         composer.append_gate(constraint);
///
///         // Check that a and b are in range
///         composer.component_range(a, 1 << 6);
///         composer.component_range(b, 1 << 5);
///
///         // Make second constraint a * b = d
///         let constraint = Constraint::new()
///             .mult(1)
///             .public(-self.d)
///             .a(a)
///             .b(b);
///
///         composer.append_gate(constraint);
///
///         let e = composer.append_witness(self.e);
///         let scalar_mul_result =
///             composer.component_mul_generator(
///                 e, dusk_jubjub::GENERATOR_EXTENDED,
///             );
///         // Apply the constraint
///         composer
///             .assert_equal_public_point(scalar_mul_result, self.f);
///         Ok(())
///     }
///
///     fn public_inputs(&self) -> Vec<PublicInputValue> {
///         vec![self.c.into(), self.d.into(), self.f.into()]
///     }
///
///     fn padded_gates(&self) -> usize {
///         1 << 11
///     }
/// }
///
/// let pp = PublicParameters::setup(1 << 12, &mut OsRng)?;
/// // Initialize the circuit
/// let mut circuit = TestCircuit::default();
/// // Compile/preprocess the circuit
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
///     circuit.prove(&pp, &pk, b"Test")
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
/// TestCircuit::verify(
///     &pp,
///     &vd,
///     &proof,
///     &public_inputs,
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
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), Error>;

    /// Compiles the circuit by using a function that returns a `Result`
    /// with the `ProverKey`, `VerifierKey` and the circuit size.
    fn compile(
        &mut self,
        pub_params: &PublicParameters,
    ) -> Result<(ProverKey, VerifierData), Error> {
        // Setup PublicParams
        let (ck, _) = pub_params.trim(self.padded_gates() + 6)?;

        // Generate & save `ProverKey` with some random values.
        let mut prover = Prover::new(b"CircuitCompilation");

        self.gadget(prover.composer_mut())?;

        let public_inputs_indexes =
            prover.composer_mut().public_input_indexes();

        prover.preprocess(&ck)?;

        // Generate & save `VerifierKey` with some random values.
        let mut verifier = Verifier::new(b"CircuitCompilation");

        self.gadget(verifier.composer_mut())?;

        verifier.preprocess(&ck)?;

        Ok((
            prover
                .prover_key
                .expect("Unexpected error. Missing ProverKey in compilation"),
            VerifierData::new(
                verifier.verifier_key.expect(
                    "Unexpected error. Missing VerifierKey in compilation",
                ),
                public_inputs_indexes,
            ),
        ))
    }

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey`
    /// instances.
    fn prove(
        &mut self,
        pub_params: &PublicParameters,
        prover_key: &ProverKey,
        transcript_init: &'static [u8],
    ) -> Result<Proof, Error> {
        let (ck, _) = pub_params.trim(self.padded_gates() + 6)?;

        // New Prover instance
        let mut prover = Prover::new(transcript_init);

        // Fill witnesses for Prover
        self.gadget(prover.composer_mut())?;

        // Add ProverKey to Prover
        prover.prover_key = Some(prover_key.clone());
        prover.prove(&ck)
    }

    /// Verify the provided proof for the compiled verifier data
    fn verify(
        pub_params: &PublicParameters,
        verifier_data: &VerifierData,
        proof: &Proof,
        public_inputs: &[PublicInputValue],
        transcript_init: &'static [u8],
    ) -> Result<(), Error> {
        let gates = verifier_data.key().padded_gates();
        let pi_indexes = verifier_data.public_inputs_indexes();

        let mut dense_pi = vec![BlsScalar::zero(); gates];

        public_inputs
            .iter()
            .map(|pi| pi.0.clone())
            .flatten()
            .zip(pi_indexes.iter().cloned())
            .for_each(|(value, pos)| {
                dense_pi[pos] = -value;
            });

        let mut verifier = Verifier::new(transcript_init);

        verifier.verifier_key.replace(*verifier_data.key());

        let opening_key = pub_params.opening_key();

        verifier.verify(proof, opening_key, &dense_pi)
    }

    /// Return the list of public inputs generated by the gadget
    fn public_inputs(&self) -> Vec<PublicInputValue>;

    /// Returns the Circuit size padded to the next power of two.
    fn padded_gates(&self) -> usize;
}
