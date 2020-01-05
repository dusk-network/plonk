use algebra::{fields::PrimeField, to_bytes, PairingEngine, ToBytes};
use merlin::Transcript;
use poly_commit::kzg10::Commitment;

pub trait TranscriptProtocol<E: PairingEngine> {
    /// Append a `commitment` with the given `label`.
    fn append_commitment(&mut self, label: &'static [u8], comm: &Commitment<E>);

    /// Append a `Scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], s: &E::Fr);

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> E::Fr;
}

impl<E: PairingEngine> TranscriptProtocol<E> for Transcript {
    fn append_commitment(&mut self, label: &'static [u8], comm: &Commitment<E>) {
        self.append_message(label, &to_bytes![comm].unwrap());
    }

    fn append_scalar(&mut self, label: &'static [u8], s: &E::Fr) {
        self.append_message(label, &to_bytes![s].unwrap())
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> E::Fr {
        use algebra::UniformRand;
        use rand_chacha::ChaChaRng;
        use rand_core::SeedableRng;

        // XXX: This is not very fast as build_rng clones the transcript each time
        // The problem is that the E::Fr::from_rand_bytes() stalls at spontaneous points
        // If we switch to bls12_381 we can generate the challenge bytes then give it to the bls function for reducing bytes to a scalar

        let mut buf = [0u8; 32];
        self.challenge_bytes(label, &mut buf);

        let mut rng = &mut self.build_rng().finalize(&mut ChaChaRng::from_seed(buf));
        E::Fr::rand(&mut rng)
    }
}
