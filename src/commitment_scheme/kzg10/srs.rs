use super::errors::Error;
use super::key::{ProverKey, VerifierKey};
use crate::multiscalar_mul_single_base;
use new_bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar};
use rand_core::RngCore;
/// Structured Reference String (SRS) is the main component in KZG10
/// It is available to both the prover and verifier
/// Allowing the verifier to efficiently verify claims about polynomials up to a configured degree
pub struct SRS {
    commit_key: ProverKey,
    verifier_key: VerifierKey,
}

impl SRS {
    /// Setup generates an SRS using a `RNG`
    /// This method will in most cases be used for testing and exploration
    /// In reality, a `trusted` party or an `MPC` is used to generate an SRS
    pub fn setup<R: RngCore>(max_degree: usize, mut rng: &mut R) -> Result<SRS, Error> {
        // Cannot commit to constants
        if max_degree < 1 {
            return Err(Error::DegreeIsZero);
        }

        // Generate the secret scalar beta
        // Seems `Scalar` does not have a method for this such as Scalar::random()
        let beta = random_scalar(&mut rng);
        // Compute powers of beta upto and including beta^max_degree
        let powers_of_beta = powers_of(beta, max_degree);

        // powers of g will be used to commit to the polynomial
        let g = random_g1_point(&mut rng);
        let powers_of_g: Vec<G1Projective> = multiscalar_mul_single_base(&powers_of_beta, g);
        assert_eq!(powers_of_g.len(), max_degree);

        // powers of gamma will be used to blind the polynomial
        let gamma_g = random_g1_point(&mut rng);
        let powers_of_gamma_g: Vec<G1Projective> =
            powers_of_beta.iter().map(|a| gamma_g * a).collect();
        assert_eq!(powers_of_gamma_g.len(), max_degree);

        // Normalise all projective points
        let mut normalised_g = vec![G1Affine::identity(); max_degree];
        G1Projective::batch_normalize(&powers_of_g, &mut normalised_g);

        let mut normalised_gamma_g = vec![G1Affine::identity(); max_degree];
        G1Projective::batch_normalize(&powers_of_gamma_g, &mut normalised_gamma_g);

        // Compute auxiliary elements to verify a proof
        let h: G2Affine = random_g2_point(&mut rng).into();
        let beta_h: G2Affine = (h * beta).into();
        let prepared_h: G2Prepared = G2Prepared::from(h);
        let prepared_beta_h = G2Prepared::from(beta_h);

        Ok(SRS {
            commit_key: ProverKey {
                powers_of_g: normalised_g,
                powers_of_gamma_g: normalised_gamma_g,
            },
            verifier_key: VerifierKey {
                g: g.into(),
                gamma_g: gamma_g.into(),
                h: h,
                beta_h: beta_h,
                prepared_h: prepared_h,
                prepared_beta_h: prepared_beta_h,
            },
        })
    }

    /// Trim truncates the prover key to allow the prover to commit to polynomials up to the
    /// and including the truncated degree
    pub fn trim(&self, truncated_degree: usize) -> Result<(ProverKey, VerifierKey), Error> {
        let truncated_prover_key = self.commit_key.truncate(truncated_degree)?;
        let verifier_key = self.verifier_key.clone();
        Ok((truncated_prover_key, verifier_key))
    }

    /// Max degree specifies the largest polynomial that a prover can commit to
    pub fn max_degree(&self) -> usize {
        self.commit_key.max_degree()
    }
}
/// Returns a vector of Scalars of increasing powers of x from x^0 to x^d
fn powers_of(mut x: Scalar, degree: usize) -> Vec<Scalar> {
    let mut powers_of_x = vec![Scalar::one()];
    for i in 1..=degree {
        powers_of_x.push(x * powers_of_x[i - 1]);
    }
    powers_of_x
}
// bls_12-381 library does not provide a `random` method for Scalar
// We wil use this helper function to compensate
pub(crate) fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    Scalar::from_raw([
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
    ])
}
// bls_12-381 library does not provide a `random` method for G1
// We wil use this helper function to compensate
pub(crate) fn random_g1_point<R: RngCore>(rng: &mut R) -> G1Projective {
    G1Affine::generator() * random_scalar(rng)
}
// bls_12-381 library does not provide a `random` method for G2
// We wil use this helper function to compensate
pub(crate) fn random_g2_point<R: RngCore>(rng: &mut R) -> G2Projective {
    G2Affine::generator() * random_scalar(rng)
}

#[test]
fn test_powers_of() {
    let x = Scalar::from(10u64);
    let degree = 100u64;

    let powers_of_x = powers_of(x, degree as usize);

    for (i, x_i) in powers_of_x.iter().enumerate() {
        assert_eq!(*x_i, x.pow(&[i as u64, 0, 0, 0]))
    }

    let last_element = powers_of_x.last().unwrap();
    assert_eq!(*last_element, x.pow(&[degree, 0, 0, 0]))
}
