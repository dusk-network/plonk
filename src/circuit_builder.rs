//! Tools & traits for PLONK circuits

use crate::commitment_scheme::kzg10::{CommitKey, OpeningKey, PublicParameters};
use crate::constraint_system::StandardComposer;
use crate::proof_system::{Proof, Prover, ProverKey, Verifier, VerifierKey};
use anyhow::{anyhow, Error, Result};
use dusk_bls12_381::Scalar as BlsScalar;
use dusk_jubjub::{AffinePoint as JubJubAffine, Scalar as JubJubScalar};
use thiserror::Error as ThisError;

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
/// #[derive(Debug, Default, Copy, Clone)]
/// pub struct SimpleSumData {
///     pub x: BlsScalar,
///     pub y: BlsScalar,
///     pub k: BlsScalar,
/// }
///
/// impl SimpleSumData {
///     pub fn witness_data(x: BlsScalar, y: BlsScalar, k: BlsScalar) -> Self {
///         Self { x, y, k }
///     }
///
///     pub fn public_data(k: BlsScalar) -> Self {
///         let mut data = Self::default();
///         data.k = k;
///         data
///     }
/// }
///
/// circuit!(
///     SimpleSumCircuit,
///     SimpleSumData,
///     b"compile-label",
///     b"init-label",
///     MAX_DEGREE,
///     fn gadget(&mut self, composer: &mut StandardComposer) -> Result<Vec<PublicInput>, Error> {
///         let mut pi = vec![];
///
///         let x = composer.add_input(self.data().x);
///         let y = composer.add_input(self.data().y);
///
///         let k = self.data().k;
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
///         pi.push(PublicInput::BlsScalar(-k, composer.circuit_size()));
///         composer.constrain_to_constant(z, BlsScalar::zero(), -k);
///
///         Ok(pi)
///     }
/// );
///
/// fn main() -> Result<(), Error> {
///     // Static circuit
///     let (size, pk, ck, vk, ok) = {
///         let pub_params = PublicParameters::setup(MAX_DEGREE, &mut rand::thread_rng())?;
///
///         let mut circuit = SimpleSumCircuit::default();
///         circuit.compile(&pub_params)?;
///
///         let size = circuit.circuit_size();
///         let pk = circuit.prover_key().as_ref().cloned().unwrap();
///         let ck = circuit.commit_key().as_ref().cloned().unwrap();
///         let vk = circuit.verifier_key().as_ref().cloned().unwrap();
///         let ok = circuit.opening_key().as_ref().cloned().unwrap();
///
///         (size, pk, ck, vk, ok)
///     };
///
///     // Prover
///     let proof = {
///         // Prove 1 + 7 = 8
///         let prover = SimpleSumData::witness_data(
///             BlsScalar::from(1u64),
///             BlsScalar::from(7u64),
///             BlsScalar::from(8u64),
///         );
///
///         SimpleSumCircuit::from(prover)
///             .prepare_prover(size, pk, ck)
///             .gen_proof()?
///     };
///
///     // Verifier
///     {
///         let verifier = SimpleSumData::public_data(BlsScalar::from(8u64));
///
///         let mut verifier = SimpleSumCircuit::from(verifier);
///         let pi = verifier.gen_public_inputs()?;
///
///         verifier
///             .prepare_verifier(size, vk, ok)
///             .verify_proof(&proof, pi.as_slice())?;
///     }
///
///     Ok(())
/// }
/// ```
macro_rules! circuit {
    ($id:ident, $data:ty, $clabel:expr, $ilabel:expr, $degree:expr, $gadget:item) => {
        #[derive(Default, Debug, Clone)]
        pub struct $id {
            data: $data,
            size: usize,
            ck: Option<CommitKey>,
            ok: Option<OpeningKey>,
            pk: Option<ProverKey>,
            vk: Option<VerifierKey>,
        }

        impl $id {
            /// Constructor
            pub fn new(data: $data) -> Self {
                Self {
                    data,
                    size: usize::default(),
                    ck: None,
                    ok: None,
                    pk: None,
                    vk: None,
                }
            }

            /// Reference to the inner data
            #[allow(dead_code)]
            pub fn data(&self) -> &$data {
                &self.data
            }

            /// Mutable reference to the inner data
            #[allow(dead_code)]
            pub fn data_mut(&mut self) -> &mut $data {
                &mut self.data
            }
        }

        impl From<$data> for $id {
            fn from(data: $data) -> $id {
                $id::new(data)
            }
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
    /// Returns the value of a PublicInput struct
    pub fn value(&self) -> Vec<BlsScalar> {
        match self {
            PublicInput::BlsScalar(scalar, _) => vec![*scalar],
            PublicInput::JubJubScalar(scalar, _) => vec![BlsScalar::from(*scalar)],
            PublicInput::AffinePoint(point, _, _) => vec![point.get_x(), point.get_y()],
        }
    }
}

/// Circuit representation for a gadget with all of the tools that it
/// should implement.
pub trait Circuit: Sized {
    /// Gadget implementation used to fill the composer.
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<Vec<PublicInput>, Error>;

    /// Compiles the circuit.
    ///
    /// Set the commit, opening, prover and verifier keys.
    ///
    /// Also, set the circuit size.
    fn compile(&mut self, pub_params: &PublicParameters) -> Result<(), Error> {
        let (ck, ok) = pub_params.trim(Self::max_degree())?;

        self.set_commit_key(ck.clone());
        self.set_opening_key(ok);

        let mut prover = Prover::new(Self::compile_label());
        let mut verifier = Verifier::new(Self::compile_label());

        self.gadget(prover.mut_cs())?;
        self.gadget(verifier.mut_cs())?;

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

    /// Generates the public inputs for a verifier.
    fn gen_public_inputs(&mut self) -> Result<Vec<PublicInput>, Error> {
        // TODO - Create a dummy composer
        let mut verifier = Verifier::new(Self::transcript_initializer());

        self.gadget(verifier.mut_cs())
    }

    /// Generates a proof using the provided `CircuitInputs` & `ProverKey` instances.
    fn gen_proof(&mut self) -> Result<Proof, Error> {
        let mut prover = Prover::new(Self::transcript_initializer());

        self.gadget(prover.mut_cs())?;

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

    /// Prepare a new instance of the circuit to generate a proof
    fn prepare_prover(mut self, size: usize, prover_key: ProverKey, commit_key: CommitKey) -> Self {
        self.set_circuit_size(size);
        self.set_prover_key(prover_key);
        self.set_commit_key(commit_key);

        self
    }

    /// Prepare a new instance of the circuit to generate a proof
    fn prepare_verifier(
        mut self,
        size: usize,
        verifier_key: VerifierKey,
        opening_key: OpeningKey,
    ) -> Self {
        self.set_circuit_size(size);
        self.set_verifier_key(verifier_key);
        self.set_opening_key(opening_key);

        self
    }

    /// Define the circuit capacity
    fn max_degree() -> usize;

    /// Define the label used to compile the circuit
    fn compile_label() -> &'static [u8];

    /// Define the label used to initialize the transcript for proof and verification
    fn transcript_initializer() -> &'static [u8];
}

/// Represents an error in the PublicParameters creation and or modification.
#[derive(ThisError, Debug)]
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
    use crate::circuit;
    use crate::constraint_system::StandardComposer;
    use crate::proof_system::{ProverKey, VerifierKey};
    use anyhow::{Error, Result};

    #[derive(Debug, Default, Copy, Clone)]
    pub struct TestCircuitData {
        pub a: BlsScalar,
        pub b: BlsScalar,
        pub c: BlsScalar,
        pub d: BlsScalar,
    }

    impl TestCircuitData {
        pub fn witness_data(a: BlsScalar, b: BlsScalar, c: BlsScalar, d: BlsScalar) -> Self {
            Self { a, b, c, d }
        }

        pub fn public_data(c: BlsScalar, d: BlsScalar) -> Self {
            let mut data = Self::default();
            data.c = c;
            data.d = d;
            data
        }
    }

    // Implements a circuit that checks:
    // 1) a + b = c where C is a PI
    // 2) a <= 2^6
    // 3) b <= 2^5
    // 4) a * b = d where D is a PI
    circuit!(
        TestCircuit,
        TestCircuitData,
        b"compile-label",
        b"init-label",
        1 << 9,
        fn gadget(&mut self, composer: &mut StandardComposer) -> Result<Vec<PublicInput>, Error> {
            let mut pi = Vec::new();

            let a = composer.add_input(self.data.a);
            let b = composer.add_input(self.data.b);

            let c = self.data.c;
            let d = self.data.d;

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
    fn test_full() -> Result<()> {
        // Generate CRS
        let pub_params = PublicParameters::setup(1 << 10, &mut rand::thread_rng())?;

        // Initialize the circuit
        let mut circuit = TestCircuit::default();
        {
            // Compile the circuit
            circuit.compile(&pub_params)?;

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

        let size = circuit.circuit_size();

        // Read the keys
        let ck = CommitKey::from_bytes(&std::fs::read("ck_testcirc")?[..]).unwrap();
        let ok = OpeningKey::from_bytes(&std::fs::read("ok_testcirc")?[..]).unwrap();
        let pk = ProverKey::from_bytes(&std::fs::read("pk_testcirc")?[..]).unwrap();
        let vk = VerifierKey::from_bytes(&std::fs::read("vk_testcirc")?[..]).unwrap();

        // Prove the statement
        // Generate the proof inputs
        let witness = TestCircuitData::witness_data(
            BlsScalar::from(25u64),
            BlsScalar::from(5u64),
            BlsScalar::from(30u64),
            BlsScalar::from(125u64),
        );
        // Generate the proof
        let proof = TestCircuit::from(witness)
            .prepare_prover(size, pk, ck)
            .gen_proof()?;

        // Verify the proof
        // Generate the public inputs
        let public = TestCircuitData::public_data(BlsScalar::from(30u64), BlsScalar::from(125u64));

        let mut verifier = TestCircuit::from(public);
        let pi = verifier.gen_public_inputs()?;

        verifier
            .prepare_verifier(size, vk, ok)
            .verify_proof(&proof, pi.as_slice())
    }
}
