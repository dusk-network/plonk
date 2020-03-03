use super::errors::Error;
use super::Commitment;
use super::{AggregateProof, Proof};
use crate::fft::Polynomial;
use crate::transcript::TranscriptProtocol;
use crate::util::powers_of;

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, Scalar};

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
    fn compute_single_witness(polynomial: &Polynomial, point: &Scalar) -> (Polynomial, Scalar) {
        // X - z
        let divisor = Polynomial::from_coefficients_vec(vec![-point, Scalar::one()]);
        // Compute f(z)
        let value = polynomial.evaluate(&point);
        // Compute witness for regular polynomial
        let witness_poly = {
            let f_minus_z = polynomial - &value;
            &f_minus_z / &divisor
        };
        (witness_poly, value)
    }

    /// Allows you to compute a witness for multiple polynomials at the same point
    /// XXX: refactor single case to use this method
    fn compute_aggregate_witness(
        polynomials: Vec<&Polynomial>,
        point: &Scalar,
        transcript: &mut dyn TranscriptProtocol,
    ) -> (Polynomial, Vec<Scalar>) {
        // X - z
        let divisor = Polynomial::from_coefficients_vec(vec![-point, Scalar::one()]);

        // Compute evaluations of polynomials
        let mut values = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            values.push(poly.evaluate(&point))
        }
        let challenge = transcript.challenge_scalar(b"");
        let powers = powers_of(&challenge, polynomials.len() - 1);

        assert_eq!(powers.len(), polynomials.len());
        assert_eq!(powers.len(), values.len());

        let numerator: Polynomial = polynomials
            .into_iter()
            .zip(values.iter())
            .zip(powers.iter())
            .map(|((poly, value), challenge)| &(poly - value) * challenge)
            .sum();
        let witness_poly = &numerator / &divisor;
        (witness_poly, values)
    }

    ///XXX: Refactor this to use open_multiple
    pub fn open_single(&self, polynomial: &Polynomial, point: &Scalar) -> Result<Proof, Error> {
        let (witness_poly, evaluated_point) = Self::compute_single_witness(polynomial, point);
        Ok(Proof {
            commitment_to_witness: self.commit(&witness_poly)?,
            evaluated_point: evaluated_point,
            commitment_to_polynomial: self.commit(polynomial)?,
        })
    }
    // Creates a proof that multiple polynomials were evaluated at the same point
    pub fn open_multiple(
        &self,
        polynomials: Vec<&Polynomial>,
        point: &Scalar,
        transcript: &mut dyn TranscriptProtocol,
    ) -> Result<AggregateProof, Error> {
        //
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            polynomial_commitments.push(self.commit(poly)?)
        }

        // Compute the aggregate Witness for polynomials
        //
        let (witness_poly, evaluations) =
            Self::compute_aggregate_witness(polynomials, point, transcript);

        // Commit to witness polynomial
        //
        let witness_commitment = self.commit(&witness_poly)?;

        let aggregate_proof = AggregateProof {
            commitment_to_witness: witness_commitment,
            evaluated_points: evaluations,
            commitments_to_polynomials: polynomial_commitments,
        };
        Ok(aggregate_proof)
    }
}

impl VerifierKey {
    // XXX: refactor this to use one pairing
    // Checks that single polynomial was evaluated at a specified point and returns the value specified.
    fn check(&self, point: Scalar, proof: Proof) -> bool {
        use bls12_381::pairing;
        let inner: G1Affine =
            (proof.commitment_to_polynomial.0 - (self.g * proof.evaluated_point)).into();
        let lhs = pairing(&inner, &self.h);

        let inner: G2Affine = (self.beta_h - (self.h * point)).into();
        let rhs = pairing(&proof.commitment_to_witness.0, &inner);

        lhs == rhs
    }

    pub fn batch_check(
        &self,
        points: &[Scalar],
        proofs: &[Proof],
        transcript: &mut dyn TranscriptProtocol,
    ) -> bool {
        let mut total_c = G1Projective::identity();
        let mut total_w = G1Projective::identity();

        let challenge = transcript.challenge_scalar(b"");
        let powers = powers_of(&challenge, proofs.len() - 1);
        // Instead of multiplying g and gamma_g in each turn, we simply accumulate
        // their coefficients and perform a final multiplication at the end.
        let mut g_multiplier = Scalar::zero();

        for ((proof, challenge), point) in proofs.iter().zip(powers).zip(points) {
            let mut c = G1Projective::from(proof.commitment_to_polynomial.0);
            let w = proof.commitment_to_witness.0;
            c = c + w * point;
            g_multiplier += challenge * proof.evaluated_point;

            total_c += c * challenge;
            total_w += w * challenge;
        }
        total_c -= self.g * g_multiplier;

        let affine_total_w = G1Affine::from(-total_w);
        let affine_total_c = G1Affine::from(total_c);

        let pairing = bls12_381::multi_miller_loop(&[
            (&affine_total_w, &self.prepared_beta_h),
            (&affine_total_c, &self.prepared_h),
        ])
        .final_exponentiation();

        pairing == bls12_381::Gt::identity()
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

mod test {
    use super::super::srs::*;
    use super::*;
    use merlin::Transcript;

    #[test]
    fn test_basic_commit() {
        let degree = 25;
        let srs = SRS::setup(degree, &mut rand::thread_rng()).unwrap();
        let (proving_key, vk) = srs.trim(degree).unwrap();

        let point = Scalar::from(10);

        // Compute secret polynomial
        let poly = Polynomial::rand(degree, &mut rand::thread_rng());

        let proof = proving_key.open_single(&poly, &point).unwrap();

        let ok = vk.check(point, proof);
        assert!(ok);
    }
    #[test]
    fn test_batch_verification() {
        let degree = 25;
        let srs = SRS::setup(degree, &mut rand::thread_rng()).unwrap();
        let (proving_key, vk) = srs.trim(degree).unwrap();
        let point_a = Scalar::from(10);
        let point_b = Scalar::from(11);
        // Compute secret polynomial a
        let poly_a = Polynomial::rand(degree, &mut rand::thread_rng());
        let proof_a = proving_key.open_single(&poly_a, &point_a).unwrap();
        assert!(vk.check(point_a, proof_a));
        // Compute secret polynomial b
        let poly_b = Polynomial::rand(degree, &mut rand::thread_rng());
        let proof_b = proving_key.open_single(&poly_b, &point_b).unwrap();
        assert!(vk.check(point_b, proof_b));

        let ok = vk.batch_check(
            &[point_a, point_b],
            &[proof_a, proof_b],
            &mut Transcript::new(b""),
        );
        assert!(ok);
    }
    #[test]
    fn test_aggregate_witness() {
        let max_degree = 100;
        let srs = SRS::setup(max_degree, &mut rand::thread_rng()).unwrap();
        let point = Scalar::from(10);
        // Prover View
        let aggregated_proof = {
            let degree = 25;
            let (ck, _) = srs.trim(degree + 2).unwrap();
            let mut transcript = Transcript::new(b"");
            // Compute secret polynomial
            let poly_a = Polynomial::rand(degree, &mut rand::thread_rng());
            let poly_b = Polynomial::rand(degree + 1, &mut rand::thread_rng());
            let poly_c = Polynomial::rand(degree + 2, &mut rand::thread_rng());

            ck.open_multiple(vec![&poly_a, &poly_b, &poly_c], &point, &mut transcript)
                .unwrap()
        };

        //Verifiers view
        let ok = {
            let vk = srs.verifier_key;
            let mut transcript = Transcript::new(b"");
            let flattened_proof = aggregated_proof.flatten(&mut transcript);
            vk.check(point, flattened_proof)
        };

        assert!(ok);
    }

    #[test]
    fn test_batch_with_aggregation() {
        let max_degree = 100;
        let srs = SRS::setup(max_degree, &mut rand::thread_rng()).unwrap();
        let point_a = Scalar::from(10);
        let point_b = Scalar::from(11);
        // Prover View
        let (aggregated_proof, single_proof) = {
            let local_max_degree = 28;
            let (ck, _) = srs.trim(local_max_degree).unwrap();
            let mut transcript = Transcript::new(b"");
            // Compute secret polynomial
            let poly_a = Polynomial::rand(25, &mut rand::thread_rng());
            let poly_b = Polynomial::rand(26, &mut rand::thread_rng());
            let poly_c = Polynomial::rand(27, &mut rand::thread_rng());
            let poly_d = Polynomial::rand(28, &mut rand::thread_rng());

            let aggregated_proof = ck
                .open_multiple(vec![&poly_a, &poly_b, &poly_c], &point_a, &mut transcript)
                .unwrap();

            let single_proof = ck.open_single(&poly_d, &point_b).unwrap();

            (aggregated_proof, single_proof)
        };

        //Verifiers view
        let ok = {
            let vk = srs.verifier_key;
            let mut transcript = Transcript::new(b"");
            let flattened_proof = aggregated_proof.flatten(&mut transcript);
            vk.batch_check(
                &[point_a, point_b],
                &[flattened_proof, single_proof],
                &mut transcript,
            )
        };

        assert!(ok);
    }
}
