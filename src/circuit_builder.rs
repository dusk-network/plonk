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
    #[allow(dead_code)]
    fn value(&self) -> Vec<BlsScalar> {
        match self {
            PublicInput::BlsScalar(scalar, _) => vec![*scalar],
            PublicInput::JubJubScalar(scalar, _) => vec![BlsScalar::from(*scalar)],
            PublicInput::AffinePoint(point, _, _) => {
                vec![point.get_x().into(), point.get_y().into()]
            }
        }
    }
}

/// Circuit representation for a gadget with all of the tools that it
/// should implement.
pub trait Circuit<'a>
where
    Self: Sized + Default,
{
    /// Gadget implementation used to fill the composer.
    fn gadget(
        &mut self,
        composer: &mut StandardComposer,
        inputs: CircuitInputs,
    ) -> Result<Vec<PublicInput>, Error>;
    /// Compiles the circuit by using a function that returns a `Result`
    /// with the `ProverKey`, `VerifierKey` and the circuit size.
    fn compile(
        &mut self,
        pub_params: &PublicParameters,
        inputs: CircuitInputs,
    ) -> Result<(ProverKey, VerifierKey, usize), Error>;

    /// Build PI vector for Proof verifications.
    fn build_pi(&self, pub_inputs: &[PublicInput]) -> Vec<BlsScalar>;

    /// Get the circuit size of the implemented circuit.
    fn circuit_size(&self) -> usize;

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey` instances.
    fn gen_proof(
        &mut self,
        pub_params: &PublicParameters,
        prover_key: &ProverKey,
        inputs: CircuitInputs,
        transcript_initialisation: &'static [u8],
    ) -> Result<Proof, Error>;

    /// Verifies a proof using the provided `CircuitInputs` & `VerifierKey` instances.
    fn verify_proof(
        &self,
        pub_params: &PublicParameters,
        verifier_key: &VerifierKey,
        transcript_initialisation: &'static [u8],
        proof: &Proof,
        pub_inputs: &[PublicInput],
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
        pi_constructor: Option<Vec<PublicInput>>,
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
            &mut self,
            composer: &mut StandardComposer,
            inputs: CircuitInputs,
        ) -> Result<Vec<PublicInput>, Error> {
            let mut pi = Vec::new();
            let a = composer.add_input(inputs.bls_scalars[0]);
            let b = composer.add_input(inputs.bls_scalars[1]);
            // Make first constraint a + b = c
            pi.push(PublicInput::BlsScalar(
                -inputs.bls_scalars[2],
                composer.circuit_size(),
            ));
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

            // Check that a and b are in range
            composer.range_gate(a, 1 << 6);
            composer.range_gate(b, 1 << 5);
            // Make second constraint a * b = d
            pi.push(PublicInput::BlsScalar(
                -inputs.bls_scalars[3],
                composer.circuit_size(),
            ));
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

            self.circuit_size = composer.circuit_size();
            Ok(pi)
        }
        fn compile(
            &mut self,
            pub_params: &PublicParameters,
            compile_inputs: CircuitInputs,
        ) -> Result<(ProverKey, VerifierKey, usize), Error> {
            // Setup PublicParams
            let (ck, _) = pub_params.trim(1 << 9)?;
            // Generate & save `ProverKey` with some random values.
            let mut prover = Prover::new(b"TestCircuit");
            // Set size & Pi builder
            self.pi_constructor = Some(self.gadget(prover.mut_cs(), compile_inputs)?);
            prover.preprocess(&ck)?;

            // Generate & save `VerifierKey` with some random values.
            let mut verifier = Verifier::new(b"TestCircuit");
            self.gadget(verifier.mut_cs(), compile_inputs)?;
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

        fn build_pi(&self, pub_inputs: &[PublicInput]) -> Vec<BlsScalar> {
            let mut pi = vec![BlsScalar::zero(); self.circuit_size];
            self.pi_constructor
                .as_ref()
                .expect("Circuit must be compiled before building PI vectors.")
                .iter()
                .enumerate()
                .for_each(|(idx, pi_constr)| {
                    match pi_constr {
                        PublicInput::BlsScalar(_, pos) => pi[*pos] = pub_inputs[idx].value()[0],
                        PublicInput::JubJubScalar(_, pos) => pi[*pos] = pub_inputs[idx].value()[0],
                        PublicInput::AffinePoint(_, pos_x, pos_y) => {
                            let (coord_x, coord_y) =
                                (pub_inputs[idx].value()[0], pub_inputs[idx].value()[1]);
                            pi[*pos_x] = coord_x;
                            pi[*pos_y] = coord_y;
                        }
                    };
                });
            pi
        }

        fn circuit_size(&self) -> usize {
            self.circuit_size
        }

        fn gen_proof(
            &mut self,
            pub_params: &PublicParameters,
            prover_key: &ProverKey,
            inputs: CircuitInputs,
            transcript_initialisation: &'static [u8],
        ) -> Result<Proof, Error> {
            let (ck, _) = pub_params.trim(1 << 9)?;
            // New Prover instance
            let mut prover = Prover::new(transcript_initialisation);
            // Fill witnesses for Prover
            self.gadget(prover.mut_cs(), inputs)?;
            // Add ProverKey to Prover
            prover.prover_key = Some(prover_key.clone());
            prover.prove(&ck)
        }

        fn verify_proof(
            &self,
            pub_params: &PublicParameters,
            verifier_key: &VerifierKey,
            transcript_initialisation: &'static [u8],
            proof: &Proof,
            pub_inputs: &[PublicInput],
        ) -> Result<(), Error> {
            let (_, vk) = pub_params.trim(1 << 9)?;
            // New Verifier instance
            let mut verifier = Verifier::new(transcript_initialisation);
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
        let public_inputs2 = vec![PublicInput::BlsScalar(-c, 0), PublicInput::BlsScalar(-d, 0)];
        let proof = circuit.gen_proof(&pub_params, &prover_key, inputs2, b"TestCirc")?;
        circuit.verify_proof(
            &pub_params,
            &verifier_key,
            b"TestCirc",
            &proof,
            &public_inputs2,
        )
    }
}
