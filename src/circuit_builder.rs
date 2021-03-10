// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Tools & traits for PLONK circuits

use crate::commitment_scheme::kzg10::PublicParameters;
use crate::constraint_system::StandardComposer;
use crate::proof_system::{Proof, ProverKey, VerifierKey};
use anyhow::Result;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubScalar};
use thiserror::Error;

const BLS_SCALAR: u8 = 1;
const JUBJUB_SCALAR: u8 = 2;
const JUBJUB_AFFINE: u8 = 3;

/// Public Input
#[derive(Debug, Copy, Clone)]
pub enum PublicInput {
    /// Scalar Input
    BlsScalar(BlsScalar, usize),
    /// Embedded Scalar Input
    JubJubScalar(JubJubScalar, usize),
    /// Point as Public Input
    AffinePoint(JubJubAffine, usize, usize),
}

impl PublicInput {
    /// Returns the serialized-size of the `PublicInput` structure.
    pub const fn serialized_size() -> usize {
        33usize
    }

    /// Returns the byte-representation of a [`PublicInput`].
    /// Note that the underlying variants of this enum have different
    /// sizes on it's byte-representation. Therefore, we need to return
    /// the biggest one to set it as the default one.
    pub fn to_bytes(&self) -> [u8; Self::serialized_size()] {
        let mut bytes = [0u8; Self::serialized_size()];
        match self {
            Self::BlsScalar(scalar, _) => {
                bytes[0] = BLS_SCALAR;
                bytes[1..33].copy_from_slice(&scalar.to_bytes());
                bytes
            }
            Self::JubJubScalar(scalar, _) => {
                bytes[0] = JUBJUB_SCALAR;
                bytes[1..33].copy_from_slice(&scalar.to_bytes());
                bytes
            }
            Self::AffinePoint(point, _, _) => {
                bytes[0] = JUBJUB_AFFINE;
                bytes[1..Self::serialized_size()].copy_from_slice(&point.to_bytes());
                bytes
            }
        }
    }

    /// Generate a [`PublicInput`] structure from it's byte representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CircuitErrors> {
        if bytes.len() < Self::serialized_size() {
            return Err(CircuitErrors::InvalidPublicInputBytes.into());
        } else {
            let mut array_bytes = [0u8; 32];
            array_bytes.copy_from_slice(&bytes[1..Self::serialized_size()]);
            match bytes[0] {
                BLS_SCALAR => BlsScalar::from_bytes(&array_bytes)
                    .map(|s| Self::BlsScalar(s, 0))
                    .map_err(|_| CircuitErrors::InvalidPublicInputBytes),

                JUBJUB_SCALAR => JubJubScalar::from_bytes(&array_bytes)
                    .map(|s| Self::JubJubScalar(s, 0))
                    .map_err(|_| CircuitErrors::InvalidPublicInputBytes),

                JUBJUB_AFFINE => JubJubAffine::from_bytes(&array_bytes)
                    .map(|s| Self::AffinePoint(s, 0, 0))
                    .map_err(|_| CircuitErrors::InvalidPublicInputBytes),

                _ => unreachable!(),
            }
        }
    }

    /// Returns the positions that of a PublicInput struct
    fn pos(&self) -> [usize; 2] {
        match self {
            PublicInput::BlsScalar(_, pos) => [*pos, 0],
            PublicInput::JubJubScalar(_, pos) => [*pos, 0],
            PublicInput::AffinePoint(_, pos_x, pos_y) => [*pos_x, *pos_y],
        }
    }
}

/// Circuit representation for a gadget with all of the tools that it
/// should implement.
pub trait Circuit<'a>
where
    Self: Sized,
{
    /// Gadget implementation used to fill the composer.
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<()>;
    /// Compiles the circuit by using a function that returns a `Result`
    /// with the `ProverKey`, `VerifierKey` and the circuit size.
    fn compile(&mut self, pub_params: &PublicParameters) -> Result<(ProverKey, VerifierKey)> {
        use crate::proof_system::{Prover, Verifier};
        // Setup PublicParams
        let (ck, _) = pub_params.trim(self.get_trim_size())?;
        // Generate & save `ProverKey` with some random values.
        let mut prover = Prover::new(b"CircuitCompilation");
        self.gadget(prover.mut_cs())?;
        prover.preprocess(&ck)?;

        // Generate & save `VerifierKey` with some random values.
        let mut verifier = Verifier::new(b"CircuitCompilation");
        self.gadget(verifier.mut_cs())?;
        verifier.preprocess(&ck)?;
        Ok((
            prover
                .prover_key
                .expect("Unexpected error. Missing ProverKey in compilation"),
            verifier
                .verifier_key
                .expect("Unexpected error. Missing VerifierKey in compilation"),
        ))
    }

    /// /// Return a mutable reference to the Public Inputs storage of the circuit.
    fn get_mut_pi_positions(&mut self) -> &mut Vec<PublicInput>;

    /// Return a reference to the Public Inputs storage of the circuit.
    fn get_pi_positions(&self) -> &Vec<PublicInput>;

    /// Build PI vector for Proof verifications.
    fn build_pi(&self, pub_inputs: &[PublicInput]) -> Result<Vec<BlsScalar>> {
        let mut pi = vec![BlsScalar::zero(); self.get_trim_size()];
        pub_inputs
            .iter()
            .zip(self.get_pi_positions())
            .for_each(|(real_value, real_pos)| {
                match real_value {
                    PublicInput::BlsScalar(value, _) => pi[real_pos.pos()[0]] = -value,
                    PublicInput::JubJubScalar(value, _) => {
                        pi[real_pos.pos()[0]] = -BlsScalar::from(*value)
                    }
                    PublicInput::AffinePoint(value, _, _) => {
                        pi[real_pos.pos()[0]] = -value.get_x();
                        pi[real_pos.pos()[1]] = -value.get_y();
                    }
                };
            });
        Ok(pi)
    }

    /// Returns the size at which we trim the `PublicParameters`
    /// to compile the circuit or perform proving/verification
    /// actions.
    fn get_trim_size(&self) -> usize;

    /// Sets the trim size that will be used by this circuit when
    /// trimming the Public Parameters.
    fn set_trim_size(&mut self, size: usize);

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey` instances.
    fn gen_proof(
        &mut self,
        pub_params: &PublicParameters,
        prover_key: &ProverKey,
        transcript_initialisation: &'static [u8],
    ) -> Result<Proof> {
        use crate::proof_system::Prover;
        let (ck, _) = pub_params.trim(self.get_trim_size())?;
        // New Prover instance
        let mut prover = Prover::new(transcript_initialisation);
        // Fill witnesses for Prover
        self.gadget(prover.mut_cs())?;
        // Add ProverKey to Prover
        prover.prover_key = Some(prover_key.clone());
        prover.prove(&ck)
    }

    /// Verifies a proof using the provided `CircuitInputs` & `VerifierKey` instances.
    fn verify_proof(
        &mut self,
        pub_params: &PublicParameters,
        verifier_key: &VerifierKey,
        transcript_initialisation: &'static [u8],
        proof: &Proof,
        pub_inputs: &[PublicInput],
    ) -> Result<()> {
        use crate::proof_system::Verifier;
        let (_, vk) = pub_params.trim(self.get_trim_size())?;
        // New Verifier instance
        let mut verifier = Verifier::new(transcript_initialisation);
        // Fill witnesses for Verifier
        self.gadget(verifier.mut_cs())?;
        let lookup_table = verifier.mut_cs().lookup_table.clone();
        verifier.verifier_key = Some(*verifier_key);
        verifier.verify(proof, &vk, &self.build_pi(pub_inputs)?, &lookup_table)
    }
}

/// Represents an error in the PublicParameters creation and or modification.
#[derive(Error, Debug)]
pub enum CircuitErrors {
    /// This error occurs when the circuit is not provided with all of the
    /// required inputs.
    #[error("missing inputs for the circuit")]
    CircuitInputsNotFound,
    /// This error occurs when we want to verify a Proof but the pi_constructor
    /// attribute is uninitialized.
    #[error("PI constructor attribute is uninitialized")]
    UninitializedPIGenerator,
    /// PublicInput serialization error
    #[error("Invalid PublicInput bytes")]
    InvalidPublicInputBytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::StandardComposer;
    use crate::proof_system::{ProverKey, VerifierKey};
    use anyhow::Result;

    // Implements a circuit that checks:
    // 1) a + b = c where C is a PI
    // 2) a <= 2^6
    // 3) b <= 2^5
    // 4) a * b = d where D is a PI
    pub struct TestCircuit<'a> {
        inputs: Option<&'a [BlsScalar]>,
        pi_positions: Vec<PublicInput>,
        trim_size: usize,
    }

    impl<'a> Default for TestCircuit<'a> {
        fn default() -> Self {
            TestCircuit {
                inputs: None,
                pi_positions: vec![],
                trim_size: 1 << 9,
            }
        }
    }

    impl<'a> Circuit<'a> for TestCircuit<'a> {
        fn gadget(&mut self, composer: &mut StandardComposer) -> Result<()> {
            let inputs = self
                .inputs
                .ok_or_else(|| CircuitErrors::CircuitInputsNotFound)?;
            let pi = self.get_mut_pi_positions();
            let a = composer.add_input(inputs[0]);
            let b = composer.add_input(inputs[1]);
            // Make first constraint a + b = c
            pi.push(PublicInput::BlsScalar(-inputs[2], composer.circuit_size()));
            composer.poly_gate(
                a,
                b,
                composer.zero_var,
                BlsScalar::zero(),
                BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
                -inputs[2],
            );

            // Check that a and b are in range
            composer.range_gate(a, 1 << 6);
            composer.range_gate(b, 1 << 5);
            // Make second constraint a * b = d
            pi.push(PublicInput::BlsScalar(-inputs[3], composer.circuit_size()));
            composer.poly_gate(
                a,
                b,
                composer.zero_var,
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
                BlsScalar::one(),
                BlsScalar::zero(),
                -inputs[3],
            );
            
            Ok(())
        }

        #[inline]
        fn get_trim_size(&self) -> usize {
            self.trim_size
        }

        fn set_trim_size(&mut self, size: usize) {
            self.trim_size = size;
        }

        fn get_mut_pi_positions(&mut self) -> &mut Vec<PublicInput> {
            &mut self.pi_positions
        }

        fn get_pi_positions(&self) -> &Vec<PublicInput> {
            &self.pi_positions
        }
    }

    #[test]
    fn test_full() -> Result<()> {
        use std::fs::{self, File};
        use std::io::Write;
        use tempdir::TempDir;

        let tmp = TempDir::new("plonk-keys-test-full")?.into_path();
        let pp_path = tmp.clone().join("pp_testcirc");
        let pk_path = tmp.clone().join("pk_testcirc");
        let vk_path = tmp.clone().join("vk_testcirc");

        // Generate CRS
        let pp_p = PublicParameters::setup(1 << 10, &mut rand::thread_rng())?;
        File::create(&pp_path).and_then(|mut f| f.write(pp_p.to_raw_bytes().as_slice()))?;

        // Read PublicParameters
        let pp = fs::read(pp_path)?;
        let pp = unsafe { PublicParameters::from_slice_unchecked(pp.as_slice())? };

        // Generate circuit compilation params
        let inputs = [
            BlsScalar::from(25u64),
            BlsScalar::from(5u64),
            BlsScalar::from(30u64),
            BlsScalar::from(125u64),
        ];

        // Initialize the circuit
        let mut circuit = TestCircuit::default();
        circuit.inputs = Some(&inputs);

        // Compile the circuit
        let (pk_p, vk_p) = circuit.compile(&pp)?;

        // Write the keys
        File::create(&pk_path).and_then(|mut f| f.write(pk_p.to_bytes().as_slice()))?;
        File::create(&vk_path).and_then(|mut f| f.write(vk_p.to_bytes().as_slice()))?;

        // Read ProverKey
        let pk = fs::read(pk_path)?;
        let pk = ProverKey::from_bytes(pk.as_slice())?;

        // Read VerifierKey
        let vk = fs::read(vk_path)?;
        let vk = VerifierKey::from_bytes(vk.as_slice())?;

        assert_eq!(pk, pk_p);
        assert_eq!(vk, vk_p);

        // Generate new inputs
        // Generate circuit compilation params
        let inputs2 = [
            BlsScalar::from(20u64),
            BlsScalar::from(5u64),
            BlsScalar::from(25u64),
            BlsScalar::from(100u64),
        ];

        let label = b"Test";

        // Prover POV
        let proof = {
            let mut circuit = TestCircuit::default();
            circuit.inputs = Some(&inputs2);
            circuit.gen_proof(&pp, &pk, label)
        }?;

        // Verifier POV
        let mut circuit = TestCircuit::default();
        circuit.inputs = Some(&inputs2);
        let public_inputs2 = vec![
            PublicInput::BlsScalar(BlsScalar::from(25u64), 0),
            PublicInput::BlsScalar(BlsScalar::from(100u64), 0),
        ];

        circuit.verify_proof(&pp, &vk, label, &proof, &public_inputs2)?;

        Ok(())
    }
}
