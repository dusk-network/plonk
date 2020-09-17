//! Tools & traits for PLONK circuits

use crate::commitment_scheme::kzg10::PublicParameters;
use crate::constraint_system::StandardComposer;
use crate::proof_system::{Proof, ProverKey, VerifierKey};
use anyhow::{Error, Result};
use dusk_bls12_381::Scalar as BlsScalar;
use dusk_jubjub::{AffinePoint as JubJubAffine, Scalar as JubJubScalar};

/// Circuit inputs
#[derive(Debug, Clone, Copy)]
pub struct CircuitInputs<'a> {
    bls_scalars: &'a [BlsScalar],
    jubjub_scalars: &'a [JubJubScalar],
    jubjub_affines: &'a [JubJubAffine],
}

/// Circuit representation for a gadget with all of the tools that it
/// should implement.
pub trait Circuit<'a>
where
    Self: Sized + Default,
{
    /// Gadget implementation used to fill the composer.
    fn gadget(
        composer: &mut StandardComposer,
        inputs: CircuitInputs,
    ) -> Result<(Vec<usize>, usize), Error>;
    /// Compiles the circuit by using a function that returns a `Result`
    /// with the `ProverKey`, `VerifierKey` and the circuit size.
    fn compile(
        &mut self,
        pub_params: &PublicParameters,
        inputs: CircuitInputs,
    ) -> Result<(ProverKey, VerifierKey, usize), Error>;

    /// Build PI vector for Proof verifications.
    fn build_pi(&self, pub_inputs: &[BlsScalar]) -> Vec<BlsScalar>;

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey` instances.
    fn gen_proof(
        &self,
        prover_key: &ProverKey,
        inputs: CircuitInputs,
        transcript_initialisation: Option<&'static [u8]>,
        pub_params: &PublicParameters,
    ) -> Result<Proof, Error>;

    /// Verifies a proof using the provided `CircuitInputs` & `VerifierKey` instances.
    fn verify_proof(
        &self,
        verifier_key: &VerifierKey,
        inputs: CircuitInputs,
        transcript_initialisation: Option<&'static [u8]>,
        pub_params: &PublicParameters,
        proof: &Proof,
        pub_inputs: &[BlsScalar],
    ) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint_system::StandardComposer;
    use crate::proof_system::{Prover, ProverKey, Verifier, VerifierKey};
    use anyhow::{Error, Result};

    // Implements a circuit that checks:
    // 1) a + b = c where C is a PI
    // 2) a <= 2^6
    // 3) b <= 2^5
    // 4) a * b = d where D is a PI
    pub struct TestCircuit {
        circuit_size: usize,
        pi_constructor: Option<Vec<usize>>,
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            TestCircuit {
                circuit_size: 0,
                pi_constructor: None,
            }
        }
    }

    impl<'a> Circuit<'a> for TestCircuit {
        fn gadget(
            composer: &mut StandardComposer,
            inputs: CircuitInputs,
        ) -> Result<(Vec<usize>, usize), Error> {
            let mut pi = Vec::new();
            let a = composer.add_input(inputs.bls_scalars[0]);
            let b = composer.add_input(inputs.bls_scalars[1]);
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
                -inputs.bls_scalars[2],
            );
            pi.push(composer.circuit_size());
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
                -inputs.bls_scalars[3],
            );
            pi.push(composer.circuit_size());
            let final_circuit_size = composer.circuit_size();
            Ok((pi, final_circuit_size))
        }
        fn compile(
            &mut self,
            pub_params: &PublicParameters,
            compile_inputs: CircuitInputs,
        ) -> Result<(ProverKey, VerifierKey, usize), Error> {
            // Setup PublicParams
            let (ck, _vk) = pub_params.trim(1 << 9)?;
            // Generate & save `ProverKey` with some random values.
            let mut prover = Prover::new(b"TestCircuit");
            // Set size & Pi builder
            let (pi, size) = TestCircuit::gadget(prover.mut_cs(), compile_inputs)?;
            self.pi_constructor = Some(pi);
            self.circuit_size = size;
            prover.preprocess(&ck)?;

            // Generate & save `VerifierKey` with some random values.
            let mut verifier = Verifier::new(b"TestCircuit");
            TestCircuit::gadget(verifier.mut_cs(), compile_inputs)?;
            verifier.preprocess(&ck).unwrap();
            Ok((
                prover
                    .prover_key
                    .expect("Unexpected error. Missing VerifierKey in compilation")
                    .clone(),
                verifier
                    .verifier_key
                    .expect("Unexpected error. Missing VerifierKey in compilation"),
                self.circuit_size,
            ))
        }

        fn build_pi(&self, pub_inputs: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut pi = vec![BlsScalar::zero(); self.circuit_size];
            unimplemented!()
            //self.pi_constructor.expect("Circuit must be compiled before.").iter().enumerate().map(|(idx, pos)| pi[pos] = )
        }

        fn gen_proof(
            &self,
            prover_key: &ProverKey,
            inputs: CircuitInputs,
            transcript_initialisation: Option<&'static [u8]>,
            pub_params: &PublicParameters,
        ) -> Result<Proof, Error> {
            let (ck, _) = pub_params.trim(1 << 9)?;
            // New Prover instance
            let mut prover =
                Prover::new(transcript_initialisation.unwrap_or_else(|| b"Default label"));
            // Fill witnesses for Prover
            Self::gadget(prover.mut_cs(), inputs)?;
            // Add ProverKey to Prover
            prover.prover_key = Some(prover_key.clone());
            prover.prove(&ck)
        }

        fn verify_proof(
            &self,
            verifier_key: &VerifierKey,
            inputs: CircuitInputs,
            transcript_initialisation: Option<&'static [u8]>,
            pub_params: &PublicParameters,
            proof: &Proof,
            pub_inputs: &[BlsScalar],
        ) -> Result<(), Error> {
            let (_, vk) = pub_params.trim(1 << 9)?;
            // New Verifier instance
            let mut verifier =
                Verifier::new(transcript_initialisation.unwrap_or_else(|| b"Default label"));
            Self::gadget(verifier.mut_cs(), inputs)?;
            verifier.verifier_key = Some(*verifier_key);
            verifier.verify(proof, &vk, &self.build_pi(pub_inputs))
        }
    }

    #[test]
    fn test_full() -> Result<(), Error> {
        // Generate CRS
        let pub_params = PublicParameters::setup(1 << 10, &mut rand::thread_rng())?;
        // Generate circuit compilation params
        let a = BlsScalar::from(25u64);
        let b = BlsScalar::from(5u64);
        let c = BlsScalar::from(30u64);
        let d = BlsScalar::from(125u64);
        let inputs = CircuitInputs {
            bls_scalars: &[a, b, c, d],
            jubjub_scalars: &[],
            jubjub_affines: &[],
        };
        // Initialize the circuit
        let mut circuit = TestCircuit::default();
        {
            // Compile the circuit
            let (prover_key, verifier_key, _) = circuit.compile(&pub_params, inputs)?;
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
        let a = BlsScalar::from(20u64);
        let b = BlsScalar::from(5u64);
        let c = BlsScalar::from(25u64);
        let d = BlsScalar::from(100u64);
        let inputs2 = CircuitInputs {
            bls_scalars: &[a, b, c, d],
            jubjub_scalars: &[],
            jubjub_affines: &[],
        };
        let proof = circuit.gen_proof(&prover_key, inputs2, None, &pub_params)?;
        circuit.verify_proof(&verifier_key, inputs2, None, &pub_params, &proof, &[c, d])
    }
}
