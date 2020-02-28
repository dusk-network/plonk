use super::errors::SRSError;
use new_bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar};
// Verifer Key
// XXX:Add docs on what it does
#[derive(Clone, Debug)]
pub struct VerifierKey {
    /// The generator of G1.
    pub g: G1Affine,
    /// The generator of G1 that is used for making a commitment hiding.
    pub gamma_g: G1Affine,
    /// The generator of G2.
    pub h: G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: G2Prepared,
}

// Prover key
// XXX:Add docs on what it does
pub struct ProverKey {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<G1Affine>,
    /// Group elements of the form `{ \beta^i \gamma G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_gamma_g: Vec<G1Affine>,
}

impl ProverKey {
    pub(crate) fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
    /// Truncates the prover key to a new max degree
    pub(crate) fn truncate(&self, mut truncated_degree: usize) -> Result<ProverKey, SRSError> {
        if truncated_degree == 1 {
            truncated_degree += 1;
        }
        // Check that the truncated degree is not zero
        if truncated_degree == 0 {
            return Err(SRSError::TruncatedDegreeIsZero);
        }

        // Check that max degree is less than truncated degree
        if truncated_degree > self.max_degree() {
            return Err(SRSError::TruncatedDegreeTooLarge);
        }
        let powers_of_g = self.powers_of_g[..=truncated_degree].to_vec();
        let powers_of_gamma_g = self.powers_of_gamma_g[..=truncated_degree].to_vec();
        Ok(Self {
            powers_of_g: powers_of_g,
            powers_of_gamma_g: powers_of_gamma_g,
        })
    }
    fn commit() {
        todo!()
    }

    fn batch_check() {
        todo!()
    }
}
