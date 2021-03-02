// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Tools & traits for PLONK circuits

mod pi_pos_holder;
mod pub_inputs;
use crate::commitment_scheme::kzg10::PublicParameters;
use crate::constraint_system::StandardComposer;
use crate::error::Error;
use crate::proof_system::{Proof, ProverKey, VerifierKey};
use dusk_bls12_381::BlsScalar;
pub use pi_pos_holder::PiPositionsHolder;
pub use pub_inputs::{PublicInputPositions, PublicInputValue};

/// Circuit representation for a gadget with all of the tools that it
/// should implement.
pub trait Circuit<'a>
where
    Self: Sized + PiPositionsHolder,
{
    /// Initialization string used to fill the transcript for both parties.
    const TRANSCRIPT_INIT: &'static [u8];
    /// Trimming size for the keys of the circuit.
    const TRIM_SIZE: usize;
    /// Gadget implementation used to fill the composer.
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error>;
    /// Compiles the circuit by using a function that returns a `Result`
    /// with the `ProverKey`, `VerifierKey` and the circuit size.
    fn compile(
        &mut self,
        pub_params: &PublicParameters,
    ) -> Result<(ProverKey, VerifierKey, PublicInputPositions), Error> {
        use crate::proof_system::{Prover, Verifier};
        // Setup PublicParams
        let (ck, _) = pub_params.trim(Self::TRIM_SIZE)?;
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
            self.get_mut_pi_positions().clone(),
        ))
    }

    /// Build PI vector for Proof verifications.
    fn build_pi(
        &self,
        pub_input_values: &[PublicInputValue],
        pub_input_pos: &PublicInputPositions,
    ) -> Vec<BlsScalar> {
        let mut pi = vec![BlsScalar::zero(); Self::TRIM_SIZE];
        pub_input_values
            .iter()
            .zip(pub_input_pos.0.iter())
            .for_each(|(real_value, real_pos)| {
                match real_value {
                    PublicInputValue::BlsScalar(value) => pi[*real_pos] = -value,
                    PublicInputValue::JubJubScalar(value) => {
                        pi[*real_pos] = -BlsScalar::from(*value)
                    }
                    PublicInputValue::AffinePoint(value) => {
                        pi[*real_pos] = -value.get_x();
                        pi[*real_pos + 1] = -value.get_y();
                    }
                };
            });
        pi
    }

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey` instances.
    fn gen_proof(
        &mut self,
        pub_params: &PublicParameters,
        prover_key: &ProverKey,
    ) -> Result<Proof, Error> {
        use crate::proof_system::Prover;
        let (ck, _) = pub_params.trim(Self::TRIM_SIZE)?;
        // New Prover instance
        let mut prover = Prover::new(Self::TRANSCRIPT_INIT);
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
        proof: &Proof,
        pub_inputs_values: &[PublicInputValue],
        pub_inputs_positions: &PublicInputPositions,
    ) -> Result<(), Error> {
        use crate::proof_system::Verifier;
        let (_, vk) = pub_params.trim(Self::TRIM_SIZE)?;

        let mut verifier = Verifier::new(Self::TRANSCRIPT_INIT);
        verifier.verifier_key = Some(*verifier_key);
        verifier.verify(
            proof,
            &vk,
            &self.build_pi(pub_inputs_values, pub_inputs_positions),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::StandardComposer;
    use crate::proof_system::{ProverKey, VerifierKey};

    // Implements a circuit that checks:
    // 1) a + b = c where C is a PI
    // 2) a <= 2^6
    // 3) b <= 2^5
    // 4) a * b = d where D is a PI
    pub struct TestCircuit {
        inputs: [BlsScalar; 4],
        pi_positions: PublicInputPositions,
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            TestCircuit {
                inputs: [BlsScalar::zero(); 4],
                pi_positions: PublicInputPositions::default(),
            }
        }
    }

    impl PiPositionsHolder for TestCircuit {
        fn get_mut_pi_positions(&mut self) -> &mut PublicInputPositions {
            &mut self.pi_positions
        }
    }

    impl Circuit<'_> for TestCircuit {
        const TRANSCRIPT_INIT: &'static [u8] = b"Test";
        const TRIM_SIZE: usize = 1 << 9;
        fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error> {
            let a = composer.add_input(self.inputs[0]);
            let b = composer.add_input(self.inputs[1]);
            // Make first constraint a + b = c
            self.push_pi(composer.circuit_size());
            composer.poly_gate(
                a,
                b,
                composer.zero_var,
                BlsScalar::zero(),
                BlsScalar::one(),
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
                Some(-self.inputs[2]),
            );
            // Check that a and b are in range
            composer.range_gate(a, 1 << 6);
            composer.range_gate(b, 1 << 5);
            // Make second constraint a * b = d
            self.push_pi(composer.circuit_size());
            composer.poly_gate(
                a,
                b,
                composer.zero_var,
                BlsScalar::one(),
                BlsScalar::zero(),
                BlsScalar::zero(),
                BlsScalar::one(),
                BlsScalar::zero(),
                Some(-self.inputs[3]),
            );

            Ok(())
        }
    }

    #[test]
    fn test_full() {
        use std::fs::{self, File};
        use std::io::Write;
        use tempdir::TempDir;

        let tmp = TempDir::new("plonk-keys-test-full").unwrap().into_path();
        let pp_path = tmp.clone().join("pp_testcirc");
        let pk_path = tmp.clone().join("pk_testcirc");
        let vk_path = tmp.clone().join("vk_testcirc");

        // Generate CRS
        let pp_p = PublicParameters::setup(1 << 10, &mut rand::thread_rng()).unwrap();
        File::create(&pp_path)
            .and_then(|mut f| f.write(pp_p.to_raw_bytes().as_slice()))
            .unwrap();

        // Read PublicParameters
        let pp = fs::read(pp_path).unwrap();
        let pp = unsafe { PublicParameters::from_slice_unchecked(pp.as_slice()).unwrap() };

        // Initialize the circuit
        let mut circuit = TestCircuit::default();

        // Compile the circuit
        let (pk_p, vk_p, pi_pos) = circuit.compile(&pp).unwrap();

        // Write the keys
        File::create(&pk_path)
            .and_then(|mut f| f.write(pk_p.to_bytes().as_slice()))
            .unwrap();
        File::create(&vk_path)
            .and_then(|mut f| f.write(vk_p.to_bytes().as_slice()))
            .unwrap();

        // Read ProverKey
        let pk = fs::read(pk_path).unwrap();
        let pk = ProverKey::from_bytes(pk.as_slice()).unwrap();

        // Read VerifierKey
        let vk = fs::read(vk_path).unwrap();
        let vk = VerifierKey::from_bytes(vk.as_slice()).unwrap();

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

        // Prover POV
        let proof = {
            let mut circuit = TestCircuit::default();
            circuit.inputs = inputs2;
            circuit.gen_proof(&pp, &pk)
        }
        .unwrap();

        // Verifier POV
        let mut circuit = TestCircuit::default();
        let public_inputs2 = vec![
            PublicInputValue::BlsScalar(BlsScalar::from(25u64)),
            PublicInputValue::BlsScalar(BlsScalar::from(100u64)),
        ];

        assert!(circuit
            .verify_proof(&pp, &vk, &proof, &public_inputs2, &pi_pos)
            .is_ok());
    }
}
