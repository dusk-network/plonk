use super::errors::Error;
use super::Commitment;
use super::Proof;
use crate::fft::Polynomial;
use crate::transcript::TranscriptProtocol;
use bls12_381::Scalar;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared};
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
        use crate::util::{multiscalar_mul, sum_points};
        let points: Vec<G1Projective> = multiscalar_mul(&polynomial.coeffs, &self.powers_of_g);
        let committed_point = sum_points(&points);
        let commitment = Commitment::from_projective(committed_point);
        Ok(commitment)
    }

    /// For a given commitment to a polynomial
    /// Computes a witness that the polynomial was evaluated at the point `z`
    /// And its output was p(z)
    /// Witness is computed as f(x) - f(z) / x-z
    fn compute_witness_single(polynomial: &Polynomial, point: &Scalar) -> Polynomial {
        // X - z
        let divisor = Polynomial::from_coefficients_vec(vec![-point, Scalar::one()]);

        // Compute witness for regular polynomial
        let witness_poly = {
            let value = polynomial.evaluate(&point);
            let f_minus_z = polynomial - &value;
            &f_minus_z / &divisor
        };
        witness_poly
    }

    /// Allows you to compute a witness for multiple polynomials at the same point
    /// XXX: refactor single case to use this method
    fn compute_witness_multiple(
        polynomials: Vec<&Polynomial>,
        point: &Scalar,
        transcript: &mut dyn TranscriptProtocol,
    ) -> Polynomial {
        // X - z
        let divisor = Polynomial::from_coefficients_vec(vec![-point, Scalar::one()]);

        // Compute evaluations of polynomials
        let mut values = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            values.push(poly.evaluate(&point))
        }
        use crate::util::powers_of;
        let challenge = transcript.challenge_scalar(b"");
        let powers = powers_of(&challenge, polynomials.len());

        assert_eq!(powers.len(), polynomials.len());
        assert_eq!(powers.len(), values.len());

        let numerator: Polynomial = polynomials
            .into_iter()
            .zip(values.into_iter())
            .zip(powers.iter())
            .map(|((poly, value), challenge)| &(poly - &value) * challenge)
            .sum();

        let witness_poly = &numerator / &divisor;
        witness_poly
    }

    /// Given a witness, we create a proof that the opening for a polynomial
    /// was evaluated correctly
    /// XXX: This function essentially just commits the witness using multiexponentiation
    /// Can we abstract it away?
    fn open_with_witness(&self, witness_poly: &Polynomial) -> Result<Proof, Error> {
        let commitment = self.commit(witness_poly)?;
        Ok(Proof {
            commitment_to_witness: commitment,
        })
    }
    ///XXX: Refactor this to use open_multiple
    pub fn open_single(&self, polynomial: &Polynomial, point: &Scalar) -> Result<Proof, Error> {
        let witness_poly = Self::compute_witness_single(polynomial, point);
        self.open_with_witness(&witness_poly)
    }
    // Creates a proof that multiple polynomials were evaluated at the correct point
    pub fn open_multiple(
        &self,
        polynomials: Vec<&Polynomial>,
        point: &Scalar,
        transcript: &mut dyn TranscriptProtocol,
    ) -> Result<Proof, Error> {
        let witness_poly = Self::compute_witness_multiple(polynomials, point, transcript);
        self.open_with_witness(&witness_poly)
    }
}

impl VerifierKey {
    // XXX: refactor this to use one pairing
    fn check(
        &self,
        commitment_to_polynomial: Commitment,
        value: Scalar,
        point: Scalar,
        proof: Proof,
    ) -> bool {
        use bls12_381::pairing;
        let inner: G1Affine = (commitment_to_polynomial.0 - (self.g * value)).into();
        let lhs = pairing(&inner, &self.h);

        let inner: G2Affine = (self.beta_h - (self.h * point)).into();
        let rhs = pairing(&proof.commitment_to_witness.0, &inner);

        lhs == rhs
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
