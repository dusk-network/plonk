use super::errors::Error;
use super::Commitment;
use crate::fft::Polynomial;
use bls12_381::{multiscalar_mul::pippenger, G1Affine, G1Projective, G2Affine, G2Prepared};
use rand_core::RngCore;

/// Verifier Key is used to verify claims made about a committed polynomial
#[derive(Clone, Debug)]
pub struct VerifierKey {
    /// The generator of G1.
    pub g: G1Affine,
    /// The generator of G2.
    pub h: G2Affine,
    /// \beta times the above generator of G2.
    pub beta_h: G2Affine,
    /// The generator of G2, prepared for use in pairings.
    pub prepared_h: G2Prepared,
    /// \beta times the above generator of G2, prepared for use in pairings.
    pub prepared_beta_h: G2Prepared,
}

/// Prover key is used to commit to a polynomial which is bounded by the max_degree parameter
/// specified when building the SRS
pub struct ProverKey {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<G1Affine>,
}

impl ProverKey {
    /// Returns the maximum degree polynomial that you can commit to
    pub(crate) fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }

    /// Truncates the prover key to a new max degree
    pub(crate) fn truncate(&self, mut truncated_degree: usize) -> Result<ProverKey, Error> {
        if truncated_degree == 1 {
            truncated_degree += 1;
        }
        // Check that the truncated degree is not zero
        if truncated_degree == 0 {
            return Err(Error::TruncatedDegreeIsZero);
        }

        // Check that max degree is less than truncated degree
        if truncated_degree > self.max_degree() {
            return Err(Error::TruncatedDegreeTooLarge);
        }

        let truncated_powers = Self {
            powers_of_g: self.powers_of_g[..=truncated_degree].to_vec(),
        };

        Ok(truncated_powers)
    }

    fn check_commit_degree_is_within_bounds(&self, poly_degree: usize) -> Result<(), Error> {
        check_degree_is_within_bounds(self.max_degree(), poly_degree)
    }

    /// Commits to a polynomial bounded by the max degree of the Prover key
    pub fn commit(&self, polynomial: &Polynomial) -> Result<Commitment, Error> {
        // Check whether we can safely commit to this polynomial
        self.check_commit_degree_is_within_bounds(polynomial.degree())?;

        // Compute commitment
        let mut commitment = pippenger(
            &self
                .powers_of_g
                .iter()
                .map(|P| G1Projective::from(P))
                .collect::<Vec<G1Projective>>(),
            &polynomial.coeffs,
        );
        Ok(Commitment::from_projective(commitment))
    }

    fn batch_check() {
        todo!()
    }
}
// Check whether the polynomial we are committing to:
// - has zero degree
// - has a degree which is more than the max supported degree
fn check_degree_is_within_bounds(max_degree: usize, poly_degree: usize) -> Result<(), Error> {
    if poly_degree == 0 {
        return Err(Error::PolynomialDegreeIsZero);
    }
    if poly_degree > max_degree {
        return Err(Error::PolynomialDegreeTooLarge);
    }
    Ok(())
}
