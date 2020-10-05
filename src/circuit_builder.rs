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
use dusk_bls12_381::Scalar as BlsScalar;
use dusk_jubjub::{AffinePoint as JubJubAffine, Scalar as JubJubScalar};
use thiserror::Error;

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
    /// Returns the value of a PublicInput struct
    pub fn value(&self) -> Vec<BlsScalar> {
        match self {
            PublicInput::BlsScalar(scalar, _) => vec![*scalar],
            PublicInput::JubJubScalar(scalar, _) => vec![BlsScalar::from(*scalar)],
            PublicInput::AffinePoint(point, _, _) => vec![point.get_x(), point.get_y()],
        }
    }

    /// Returns the positions that of a PublicInput struct
    pub fn pos(&self) -> Vec<usize> {
        match self {
            PublicInput::BlsScalar(_, pos) => vec![*pos],
            PublicInput::JubJubScalar(_, pos) => vec![*pos],
            PublicInput::AffinePoint(_, pos_x, pos_y) => vec![*pos_x, *pos_y],
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
        let (ck, _) = pub_params.trim(self.trim_size())?;
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
        let mut pi = vec![BlsScalar::zero(); self.trim_size()];
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
    fn trim_size(&self) -> usize;

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey` instances.
    fn gen_proof(
        &mut self,
        pub_params: &PublicParameters,
        prover_key: &ProverKey,
        transcript_initialisation: &'static [u8],
    ) -> Result<Proof> {
        use crate::proof_system::Prover;
        let (ck, _) = pub_params.trim(self.trim_size())?;
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
        let (_, vk) = pub_params.trim(self.trim_size())?;
        // New Verifier instance
        let mut verifier = Verifier::new(transcript_initialisation);
        // Fill witnesses for Verifier
        self.gadget(verifier.mut_cs())?;
        verifier.verifier_key = Some(*verifier_key);
        verifier.verify(proof, &vk, &self.build_pi(pub_inputs)?)
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
    }

    impl<'a> Default for TestCircuit<'a> {
        fn default() -> Self {
            TestCircuit {
                inputs: None,
                pi_positions: vec![],
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
        fn trim_size(&self) -> usize {
            1 << 9
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
        // Generate CRS
        let pub_params = PublicParameters::setup(1 << 10, &mut rand::thread_rng())?;

        {
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
            let (prover_key, verifier_key) = circuit.compile(&pub_params)?;
            // Write the keys
            use std::fs::File;
            use std::io::Write;
            let mut prover_file = File::create("pk_testcirc")?;
            prover_file.write(prover_key.to_bytes()[..].as_ref())?;
            let mut verifier_file = File::create("vk_testcirc")?;
            verifier_file.write(verifier_key.to_bytes().as_ref())?;
        };

        // Read ProverKey
        let prover_key = ProverKey::from_bytes(&std::fs::read("pk_testcirc")?[..]).unwrap();
        // Read VerifierKey
        let verifier_key = VerifierKey::from_bytes(&std::fs::read("vk_testcirc")?[..]).unwrap();

        // Generate new inputs
        // Generate circuit compilation params
        let inputs2 = [
            BlsScalar::from(20u64),
            BlsScalar::from(5u64),
            BlsScalar::from(25u64),
            BlsScalar::from(100u64),
        ];

        // Prover POV
        let proof = {
            let mut circuit = TestCircuit::default();
            circuit.inputs = Some(&inputs2);
            circuit.gen_proof(&pub_params, &prover_key, b"Test")
        }?;

        // Verifier POV
        let mut circuit = TestCircuit::default();
        circuit.inputs = Some(&inputs2);
        let public_inputs2 = vec![
            PublicInput::BlsScalar(BlsScalar::from(25u64), 0),
            PublicInput::BlsScalar(BlsScalar::from(100u64), 0),
        ];
        circuit.verify_proof(&pub_params, &verifier_key, b"Test", &proof, &public_inputs2)
    }
}
