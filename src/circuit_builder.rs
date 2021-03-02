// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Tools & traits for PLONK circuits

mod pub_inputs;
use crate::commitment_scheme::kzg10::PublicParameters;
use crate::constraint_system::StandardComposer;
use crate::error::Error;
use crate::proof_system::{Proof, ProverKey, VerifierKey};
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubScalar};
pub use pub_inputs::PublicInput;

/// Circuit representation for a gadget with all of the tools that it
/// should implement.
pub trait Circuit<'a>
where
    Self: Sized,
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
    ) -> Result<(ProverKey, VerifierKey), Error> {
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
    fn build_pi(&self, pub_inputs: &[PublicInput]) -> Vec<BlsScalar> {
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
        pi
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
    ) -> Result<Proof, Error> {
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
    ) -> Result<(), Error> {
        use crate::proof_system::Verifier;
        let (_, vk) = pub_params.trim(self.get_trim_size())?;
        // New Verifier instance
        let mut verifier = Verifier::new(transcript_initialisation);
        // Fill witnesses for Verifier
        self.gadget(verifier.mut_cs())?;
        verifier.verifier_key = Some(*verifier_key);
        verifier.verify(proof, &vk, &self.build_pi(pub_inputs))
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
        fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error> {
            let inputs = self.inputs.ok_or_else(|| Error::CircuitInputsNotFound)?;
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

            plonk_gadgets::conditionally_select_zero(composer, a, b);
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

        // Generate circuit compilation params
        let inputs = [
            BlsScalar::from(0u64),
            BlsScalar::from(0u64),
            BlsScalar::from(0u64),
            BlsScalar::from(0u64),
        ];

        // Initialize the circuit
        let mut circuit = TestCircuit::default();
        circuit.inputs = Some(&inputs);

        // Compile the circuit
        let (pk_p, vk_p) = circuit.compile(&pp).unwrap();

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

        let label = b"Test";

        // Prover POV
        let proof = {
            let mut circuit = TestCircuit::default();
            circuit.inputs = Some(&inputs2);
            circuit.gen_proof(&pp, &pk, label)
        }
        .unwrap();

        // Verifier POV
        let mut circuit = TestCircuit::default();
        circuit.inputs = Some(&inputs2);
        let public_inputs2 = vec![
            PublicInput::BlsScalar(BlsScalar::from(25u64), 0),
            PublicInput::BlsScalar(BlsScalar::from(100u64), 0),
        ];

        circuit
            .verify_proof(&pp, &vk, label, &proof, &public_inputs2)
            .unwrap();
    }
}
