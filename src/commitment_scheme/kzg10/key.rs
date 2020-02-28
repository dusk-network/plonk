use super::errors::Error;
use super::BlindingPolynomial;
use super::Commitment;
use new_bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, Scalar};
use rand_core::RngCore;
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
    /// Returns the maximum degree polynomial that you can commit to
    pub(crate) fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }
    /// Returns the maximum hiding degree polynomial that you can
    /// blind your commitment with
    pub(crate) fn max_hiding_degree(&self) -> usize {
        self.powers_of_gamma_g.len() - 1
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
        let powers_of_g = self.powers_of_g[..=truncated_degree].to_vec();
        let powers_of_gamma_g = self.powers_of_gamma_g[..=truncated_degree].to_vec();
        Ok(Self {
            powers_of_g: powers_of_g,
            powers_of_gamma_g: powers_of_gamma_g,
        })
    }

    fn check_commit_degree_is_within_bounds(&self, poly_degree: usize) -> Result<(), Error> {
        check_degree_is_within_bounds(self.max_degree(), poly_degree)
    }
    fn check_hiding_degree_is_within_bounds(&self, hiding_degree: usize) -> Result<(), Error> {
        check_degree_is_within_bounds(self.max_hiding_degree(), hiding_degree)
    }

    ///  Commits to a polynomial bounded by the max degree of the Prover key
    /// Optionally, the user can unconditionally hide the commitment
    /// using the hiding_parameter (hiding_degree, rng)
    /// hiding_degree is the degree of the polynomial that will be used to hide the original polynomial
    pub fn commit(
        &self,
        polynomial: Vec<Scalar>,
        hiding_parameters: Option<(usize, &mut dyn RngCore)>,
    ) -> Result<(Commitment, Option<BlindingPolynomial>), Error> {
        // Check whether we can safely commit to this polynomial
        let poly_degree = polynomial.len() - 1;
        self.check_commit_degree_is_within_bounds(poly_degree)?;

        // Compute commitment
        use crate::multiscalar_mul;
        let points: Vec<G1Projective> = multiscalar_mul(&polynomial, &self.powers_of_g);
        let mut commitment = G1Projective::identity();
        for point in points {
            commitment = commitment + point;
        }

        // Compute Blinding Polynomial if hiding parameters supplied
        if let None = hiding_parameters {
            return Ok((Commitment::from_projective(commitment), None));
        };
        let (hiding_degree, mut rng) = hiding_parameters.unwrap();
        self.check_hiding_degree_is_within_bounds(hiding_degree)?;
        let blinding_poly = BlindingPolynomial::rand(hiding_degree, &mut rng);
        let points: Vec<G1Projective> = multiscalar_mul(&blinding_poly.0, &self.powers_of_gamma_g);
        let mut random_commitment = G1Projective::identity();
        for point in points {
            random_commitment = random_commitment + point;
        }
        commitment += random_commitment;

        Ok((Commitment::from_projective(commitment), Some(blinding_poly)))
    }

    fn batch_check() {
        todo!()
    }
}
// Check whether the polynomial we are committing to:
// - has zero degree
// - has a degree which is more than the max supported degree
fn check_degree_is_within_bounds(max_degree: usize, degree: usize) -> Result<(), Error> {
    if degree == 0 {
        return Err(Error::PolynomialDegreeIsZero);
    }
    if degree > max_degree {
        return Err(Error::PolynomialDegreeTooLarge);
    }
    Ok(())
}
