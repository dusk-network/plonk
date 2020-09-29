//! Tools & traits for PLONK circuits

use crate::commitment_scheme::kzg10::{CommitKey, OpeningKey, PublicParameters};
use crate::constraint_system::StandardComposer;
use crate::proof_system::{Proof, Prover, ProverKey, Verifier, VerifierKey};
use anyhow::{anyhow, Error, Result};
use dusk_bls12_381::Scalar as BlsScalar;
use dusk_jubjub::{AffinePoint as JubJubAffine, Scalar as JubJubScalar};

#[macro_export]
/// Wrapper macro to build static plonk circuits.
///
/// # Example
///
/// ```
/// use anyhow::Error;
/// use dusk_plonk::circuit;
/// use dusk_plonk::prelude::*;
///
/// const MAX_DEGREE: usize = 8;
///
/// circuit!(
///     SimpleSumCircuit,
///     b"compile-label",
///     b"init-label",
///     MAX_DEGREE,
///     fn gadget(
///         &mut self,
///         composer: &mut StandardComposer,
///         input: &CircuitInputs,
///     ) -> Result<Vec<PublicInput>, Error> {
///         let mut pi = vec![];
///
///         let x = input.bls_scalars[0];
///         let y = input.bls_scalars[1];
///         let k = input.bls_scalars[2];
///
///         let x = composer.add_input(x);
///         let y = composer.add_input(y);
///
///         // z = x + y
///         let z = composer.add(
///             (BlsScalar::one(), x),
///             (BlsScalar::one(), y),
///             BlsScalar::zero(),
///             BlsScalar::zero(),
///         );
///
///         // z == k
///         pi.push(PublicInput::BlsScalar(-k, 4));
///         composer.constrain_to_constant(z, BlsScalar::zero(), -k);
///
///         Ok(pi)
///     }
/// );
///
/// fn main() -> Result<(), Error> {
///     // Static circuit
///     let circuit = {
///         let pub_params = PublicParameters::setup(MAX_DEGREE, &mut rand::thread_rng())?;
///
///         let mut circuit = SimpleSumCircuit::default();
///         circuit.compile(
///             &pub_params,
///             &CircuitInputs::new(&[BlsScalar::zero(); 3], &[], &[]),
///         )?;
///
///         circuit
///     };
///
///     // Prover
///     let proof = {
///         let mut prover_circuit = circuit.clone();
///
///         // Prove 1 + 7 = 8
///         let witness_data = [
///             BlsScalar::from(1u64),
///             BlsScalar::from(7u64),
///             BlsScalar::from(8u64), // Intended to be public
///         ];
///         let inputs = CircuitInputs::new(&witness_data, &[], &[]);
///
///         prover_circuit.gen_proof(&inputs)?
///     };
///
///     // Verifier
///     {
///         let mut verifier_circuit = circuit.clone();
///
///         let public_data = vec![PublicInput::BlsScalar(-BlsScalar::from(8u64), 4)];
///         verifier_circuit.verify_proof(&proof, public_data.as_slice())?;
///     }
///
///     Ok(())
/// }
/// ```
macro_rules! circuit {
    ($id:ident, $clabel:expr, $ilabel:expr, $degree:expr, $gadget:item) => {
        #[derive(Default, Debug, Clone)]
        pub struct $id {
            size: usize,
            ck: Option<CommitKey>,
            ok: Option<OpeningKey>,
            pk: Option<ProverKey>,
            vk: Option<VerifierKey>,
        }

        impl Circuit for $id {
            $gadget

            fn circuit_size(&self) -> usize {
                self.size
            }

            fn set_circuit_size(&mut self, circuit_size: usize) {
                self.size = circuit_size;
            }

            fn commit_key(&self) -> &Option<CommitKey> {
                &self.ck
            }

            fn set_commit_key(&mut self, ck: CommitKey) {
                self.ck.replace(ck);
            }

            fn opening_key(&self) -> &Option<OpeningKey> {
                &self.ok
            }

            fn set_opening_key(&mut self, ok: OpeningKey) {
                self.ok.replace(ok);
            }

            fn prover_key(&self) -> &Option<ProverKey> {
                &self.pk
            }

            fn set_prover_key(&mut self, pk: ProverKey) {
                self.pk.replace(pk);
            }

            fn verifier_key(&self) -> &Option<VerifierKey> {
                &self.vk
            }

            fn set_verifier_key(&mut self, vk: VerifierKey) {
                self.vk.replace(vk);
            }

            fn compile_label() -> &'static [u8] {
                $clabel
            }

            fn transcript_initializer() -> &'static [u8] {
                $ilabel
            }

            fn max_degree() -> usize {
                $degree
            }
        }
    };
}

/// Circuit inputs
#[derive(Default, Debug, Clone, Copy)]
pub struct CircuitInputs<'a> {
    /// BLS scalars
    pub bls_scalars: &'a [BlsScalar],
    /// JubJub scalars
    pub jubjub_scalars: &'a [JubJubScalar],
    /// JubJub points
    pub jubjub_affines: &'a [JubJubAffine],
}

impl<'a> CircuitInputs<'a> {
    /// Constructor for the circuit inputs
    pub fn new(
        bls_scalars: &'a [BlsScalar],
        jubjub_scalars: &'a [JubJubScalar],
        jubjub_affines: &'a [JubJubAffine],
    ) -> Self {
        Self {
            bls_scalars,
            jubjub_scalars,
            jubjub_affines,
        }
    }
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
            PublicInput::AffinePoint(point, _, _) => vec![point.get_x(), point.get_y()],
        }
    }
}

/// Circuit representation for a gadget with all of the tools that it
/// should implement.
pub trait Circuit {
    /// Gadget implementation used to fill the composer.
    fn gadget(
        &mut self,
        composer: &mut StandardComposer,
        inputs: &CircuitInputs,
    ) -> Result<Vec<PublicInput>, Error>;

    /// Compiles the circuit.
    ///
    /// Set the commit, opening, prover and verifier keys.
    ///
    /// Also, set the circuit size.
    fn compile(
        &mut self,
        pub_params: &PublicParameters,
        inputs: &CircuitInputs,
    ) -> Result<(), Error> {
        let (ck, ok) = pub_params.trim(Self::max_degree())?;

        self.set_commit_key(ck.clone());
        self.set_opening_key(ok);

        let mut prover = Prover::new(Self::compile_label());
        let mut verifier = Verifier::new(Self::compile_label());

        self.gadget(prover.mut_cs(), inputs)?;
        self.gadget(verifier.mut_cs(), inputs)?;

        let size = prover.mut_cs().circuit_size();
        self.set_circuit_size(size + 3);

        prover.preprocess(&ck)?;
        verifier.preprocess(&ck)?;

        let pk = prover
            .prover_key
            .ok_or(anyhow!("Prover key is missing after preprocessing!"))?;

        let vk = verifier
            .verifier_key
            .ok_or(anyhow!("Verifier key is missing after preprocessing!"))?;

        self.set_prover_key(pk);
        self.set_verifier_key(vk);

        Ok(())
    }

    /// Build PI vector for Proof verifications.
    fn build_pi(&self, pub_inputs: &[PublicInput]) -> Vec<BlsScalar> {
        let mut pi = vec![BlsScalar::zero(); self.circuit_size()];

        pub_inputs.iter().for_each(|p| match p {
            PublicInput::BlsScalar(s, pos) => pi[*pos] = *s,
            PublicInput::JubJubScalar(s, pos) => pi[*pos] = BlsScalar::from(*s),
            PublicInput::AffinePoint(p, pos_x, pos_y) => {
                pi[*pos_x] = p.get_x();
                pi[*pos_y] = p.get_y();
            }
        });

        pi
    }

    /// Get the circuit size of the implemented circuit.
    fn circuit_size(&self) -> usize;

    /// Set the circuit size of the implemented circuit.
    fn set_circuit_size(&mut self, circuit_size: usize);

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey` instances.
    fn gen_proof(&mut self, inputs: &CircuitInputs) -> Result<Proof, Error> {
        let mut prover = Prover::new(Self::transcript_initializer());

        self.gadget(prover.mut_cs(), inputs)?;

        prover.prover_key = self.prover_key().as_ref().cloned();
        self.commit_key()
            .as_ref()
            .ok_or(anyhow!("Commit key not generated"))
            .and_then(|ck| prover.prove(ck))
    }

    /// Verifies a proof using the provided `CircuitInputs` & `VerifierKey` instances.
    fn verify_proof(&mut self, proof: &Proof, pub_inputs: &[PublicInput]) -> Result<(), Error> {
        let pi = self.build_pi(pub_inputs);
        let mut verifier = Verifier::new(Self::transcript_initializer());

        verifier.verifier_key = self.verifier_key().as_ref().cloned();
        self.opening_key()
            .as_ref()
            .ok_or(anyhow!("Opening key not generated"))
            .and_then(|ok| verifier.verify(proof, ok, pi.as_slice()))
    }

    /// Commit key generated by `compile`
    fn commit_key(&self) -> &Option<CommitKey>;

    /// Setter for commit key generated by `compile`
    fn set_commit_key(&mut self, ck: CommitKey);

    /// Opening key generated by `compile`
    fn opening_key(&self) -> &Option<OpeningKey>;

    /// Setter for opening key generated by `compile`
    fn set_opening_key(&mut self, ok: OpeningKey);

    /// Prover key generated by `compile`
    fn prover_key(&self) -> &Option<ProverKey>;

    /// Setter for prover key generated by `compile`
    fn set_prover_key(&mut self, pk: ProverKey);

    /// Verifier key generated by `compile`
    fn verifier_key(&self) -> &Option<VerifierKey>;

    /// Setter for verifier key generated by `compile`
    fn set_verifier_key(&mut self, vk: VerifierKey);

    /// Define the circuit capacity
    fn max_degree() -> usize;

    /// Define the label used to compile the circuit
    fn compile_label() -> &'static [u8];

    /// Define the label used to initialize the transcript for proof and verification
    fn transcript_initializer() -> &'static [u8];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit;
    use crate::constraint_system::StandardComposer;
    use crate::proof_system::{ProverKey, VerifierKey};
    use anyhow::{Error, Result};

    // Implements a circuit that checks:
    // 1) a + b = c where C is a PI
    // 2) a <= 2^6
    // 3) b <= 2^5
    // 4) a * b = d where D is a PI
    circuit!(
        TestCircuit,
        b"compile-label",
        b"init-label",
        1 << 9,
        fn gadget(
            &mut self,
            composer: &mut StandardComposer,
            inputs: &CircuitInputs,
        ) -> Result<Vec<PublicInput>, Error> {
            let mut pi = Vec::new();

            let a = composer.add_input(inputs.bls_scalars[0]);
            let b = composer.add_input(inputs.bls_scalars[1]);

            let c = inputs.bls_scalars[2];
            let d = inputs.bls_scalars[3];

            // Make first constraint a + b = c
            let x = composer.add(
                (BlsScalar::one(), a),
                (BlsScalar::one(), b),
                BlsScalar::zero(),
                BlsScalar::zero(),
            );
            pi.push(PublicInput::BlsScalar(-c, composer.circuit_size()));
            composer.constrain_to_constant(x, BlsScalar::zero(), -c);

            // Check that a and b are in range
            composer.range_gate(a, 1 << 6);
            composer.range_gate(b, 1 << 5);

            // Make second constraint a * b = d
            let y = composer.mul(BlsScalar::one(), a, b, BlsScalar::zero(), BlsScalar::zero());
            pi.push(PublicInput::BlsScalar(-d, composer.circuit_size()));
            composer.constrain_to_constant(y, BlsScalar::zero(), -d);

            Ok(pi)
        }
    );

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
            circuit.compile(&pub_params, &inputs)?;

            let commit_key = circuit.commit_key().as_ref().cloned().unwrap();
            let opening_key = circuit.opening_key().as_ref().cloned().unwrap();
            let prover_key = circuit.prover_key().as_ref().cloned().unwrap();
            let verifier_key = circuit.verifier_key().as_ref().cloned().unwrap();

            // Write the keys
            use std::fs::File;
            use std::io::Write;

            let mut commit_file = File::create("ck_testcirc")?;
            commit_file.write(commit_key.to_bytes()[..].as_ref())?;

            let mut opening_file = File::create("ok_testcirc")?;
            opening_file.write(opening_key.to_bytes()[..].as_ref())?;

            let mut prover_file = File::create("pk_testcirc")?;
            prover_file.write(prover_key.to_bytes()[..].as_ref())?;

            let mut verifier_file = File::create("vk_testcirc")?;
            verifier_file.write(verifier_key.to_bytes().as_ref())?;
        };

        // Read the keys
        let commit_key = CommitKey::from_bytes(&std::fs::read("ck_testcirc")?[..]).unwrap();
        let opening_key = OpeningKey::from_bytes(&std::fs::read("ok_testcirc")?[..]).unwrap();
        let prover_key = ProverKey::from_bytes(&std::fs::read("pk_testcirc")?[..]).unwrap();
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

        let public_inputs2 = vec![
            PublicInput::BlsScalar(-c, 4),
            PublicInput::BlsScalar(-d, 22),
        ];

        let circuit_size = circuit.circuit_size();

        // Prover perspective
        let mut prover_circuit = TestCircuit::default();
        prover_circuit.set_circuit_size(circuit_size);
        prover_circuit.set_prover_key(prover_key);
        prover_circuit.set_commit_key(commit_key);
        let proof = prover_circuit.gen_proof(&inputs2)?;

        // Verifier perspective
        let mut verifier_circuit = TestCircuit::default();
        verifier_circuit.set_circuit_size(circuit_size);
        verifier_circuit.set_verifier_key(verifier_key);
        verifier_circuit.set_opening_key(opening_key);
        verifier_circuit.verify_proof(&proof, &public_inputs2)
    }
}
