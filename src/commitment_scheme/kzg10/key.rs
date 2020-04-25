//! Key module contains the ultilities and data structures
//! that support the generation and usage of Prover and
//! Verifier keys.
use super::{errors::Error, AggregateProof, Commitment, Proof};
use crate::{fft::Polynomial, transcript::TranscriptProtocol, util};
use dusk-bls12_381::{
    multiscalar_mul::msm_variable_base, G1Affine, G1Projective, G2Affine, G2Prepared, Scalar,
};

/// Verifier Key is used to verify claims made about a committed polynomial.
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

#[cfg(feature = "serde")]
use serde::{
    self, de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};

#[cfg(feature = "serde")]
impl Serialize for VerifierKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut verif_key = serializer.serialize_struct("struct VerifierKey", 5)?;
        verif_key.serialize_field("g", &self.g)?;
        verif_key.serialize_field("h", &self.h)?;
        verif_key.serialize_field("beta_h", &self.beta_h)?;
        verif_key.serialize_field("prepared_h", &self.prepared_h)?;
        verif_key.serialize_field("prepared_beta_h", &self.prepared_beta_h)?;
        verif_key.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for VerifierKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            G,
            H,
            BetaH,
            PreparedH,
            PreparedBetaH,
        };

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        formatter.write_str("struct VerifierKey")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "g" => Ok(Field::G),
                            "h" => Ok(Field::H),
                            "beta_h" => Ok(Field::BetaH),
                            "prepared_h" => Ok(Field::PreparedH),
                            "prepared_beta_h" => Ok(Field::PreparedBetaH),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct VerifierKeyVisitor;

        impl<'de> Visitor<'de> for VerifierKeyVisitor {
            type Value = VerifierKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct VerifierKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<VerifierKey, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let g = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let h = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let beta_h = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let prepared_h = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let prepared_beta_h = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(VerifierKey {
                    g,
                    h,
                    beta_h,
                    prepared_h,
                    prepared_beta_h,
                })
            }
        }

        const FIELDS: &[&str] = &["g", "h", "beta_h", "prepared_h", "prepared_beta_h"];
        deserializer.deserialize_struct("VerifierKey", FIELDS, VerifierKeyVisitor)
    }
}

/// Prover key is used to commit to a polynomial which is bounded by the max_degree.
#[derive(Debug)]
pub struct ProverKey {
    /// Group elements of the form `{ \beta^i G }`, where `i` ranges from 0 to `degree`.
    pub powers_of_g: Vec<G1Affine>,
}

#[cfg(feature = "serde")]
use serde::ser::SerializeSeq;

#[cfg(feature = "serde")]
impl Serialize for ProverKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_seq(Some(self.powers_of_g.len()))?;
        for power in &self.powers_of_g {
            tup.serialize_element(&power)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ProverKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProverKeyVisitor;

        impl<'de> Visitor<'de> for ProverKeyVisitor {
            type Value = ProverKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a prover key with valid powers per points")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<ProverKey, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut powers_vec = Vec::new();
                // Visit each element in the inner array and push it onto
                // the existing vector.
                while let Some(elem) = seq.next_element()? {
                    powers_vec.push(elem)
                }
                Ok(ProverKey {
                    powers_of_g: powers_vec,
                })
            }
        }

        deserializer.deserialize_seq(ProverKeyVisitor)
    }
}

impl ProverKey {
    /// Returns the maximum degree polynomial that you can commit to.
    pub fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }

    /// Truncates the prover key to a lower max degree.
    /// Returns an error if the truncated degree is zero or if the truncated degree
    /// is larger than the max degree of the prover key.
    pub fn truncate(&self, mut truncated_degree: usize) -> Result<ProverKey, Error> {
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

    /// Commits to a polynomial returning the corresponding `Commitment`.
    ///
    /// Returns an error if the polynomial's degree is more than the max degree of the prover key.
    pub fn commit(&self, polynomial: &Polynomial) -> Result<Commitment, Error> {
        // Check whether we can safely commit to this polynomial
        self.check_commit_degree_is_within_bounds(polynomial.degree())?;

        // Compute commitment
        let commitment = msm_variable_base(&self.powers_of_g, &polynomial.coeffs);
        Ok(Commitment::from_projective(commitment))
    }

    /// For a given polynomial `p` and a point `z`, compute the witness
    /// for p(z) using Ruffini's method for simplicity.
    /// The Witness is the quotient of f(x) - f(z) / x-z.
    /// However we note that the quotient polynomial is invariant under the value f(z)
    /// ie. only the remainder changes. We can therefore compute the witness as f(x) / x - z
    /// and only use the remainder term f(z) during verification.
    pub fn compute_single_witness(&self, polynomial: &Polynomial, point: &Scalar) -> Polynomial {
        // Computes `f(x) / x-z`, returning it as the witness poly
        polynomial.ruffini(*point)
    }

    /// Computes a single witness for multiple polynomials at the same point, by taking
    /// a random linear combination of the individual witnesses.
    /// We apply the same optimisation mentioned in when computing each witness; removing f(z).
    pub(crate) fn compute_aggregate_witness(
        &self,
        polynomials: &[Polynomial],
        point: &Scalar,
        transcript: &mut dyn TranscriptProtocol,
    ) -> Polynomial {
        let challenge = transcript.challenge_scalar(b"aggregate_witness");
        let powers = util::powers_of(&challenge, polynomials.len() - 1);

        assert_eq!(powers.len(), polynomials.len());

        let numerator: Polynomial = polynomials
            .iter()
            .zip(powers.iter())
            .map(|(poly, challenge)| poly * challenge)
            .sum();
        numerator.ruffini(*point)
    }

    /// Creates an opening proof that a polynomial `p` was correctly evaluated at p(z) and produced the value
    /// `v`. ie v = p(z).
    /// Returns an error if the polynomials degree is too large.
    pub fn open_single(
        &self,
        polynomial: &Polynomial,
        value: &Scalar,
        point: &Scalar,
    ) -> Result<Proof, Error> {
        let witness_poly = self.compute_single_witness(polynomial, point);
        Ok(Proof {
            commitment_to_witness: self.commit(&witness_poly)?,
            evaluated_point: *value,
            commitment_to_polynomial: self.commit(polynomial)?,
        })
    }

    /// Creates an opening proof that multiple polynomials were evaluated at the same point
    /// and that each evaluation produced the correct evaluation point.
    /// Returns an error if any of the polynomial's degrees are too large.
    pub fn open_multiple(
        &self,
        polynomials: &[Polynomial],
        evaluations: Vec<Scalar>,
        point: &Scalar,
        transcript: &mut dyn TranscriptProtocol,
    ) -> Result<AggregateProof, Error> {
        // Commit to polynomials
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            polynomial_commitments.push(self.commit(poly)?)
        }

        // Compute the aggregate witness for polynomials
        let witness_poly = self.compute_aggregate_witness(polynomials, point, transcript);

        // Commit to witness polynomial
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
    /// Checks that a polynomial `p` was evaluated at a point `z` and returned the value specified `v`.
    /// ie. v = p(z).
    pub fn check(&self, point: Scalar, proof: Proof) -> bool {
        let inner_a: G1Affine =
            (proof.commitment_to_polynomial.0 - (self.g * proof.evaluated_point)).into();

        let inner_b: G2Affine = (self.beta_h - (self.h * point)).into();
        let prepared_inner_b = G2Prepared::from(-inner_b);

        let pairing = dusk-bls12_381::multi_miller_loop(&[
            (&inner_a, &self.prepared_h),
            (&proof.commitment_to_witness.0, &prepared_inner_b),
        ])
        .final_exponentiation();

        pairing == dusk-bls12_381::Gt::identity()
    }

    /// Checks whether a batch of polynomials evaluated at different points, returned their specified value.
    pub fn batch_check(
        &self,
        points: &[Scalar],
        proofs: &[Proof],
        transcript: &mut dyn TranscriptProtocol,
    ) -> bool {
        let mut total_c = G1Projective::identity();
        let mut total_w = G1Projective::identity();

        let challenge = transcript.challenge_scalar(b"batch"); // XXX: Verifier can add their own randomness at this point
        let powers = util::powers_of(&challenge, proofs.len() - 1);
        // Instead of multiplying g and gamma_g in each turn, we simply accumulate
        // their coefficients and perform a final multiplication at the end.
        let mut g_multiplier = Scalar::zero();

        for ((proof, challenge), point) in proofs.iter().zip(powers).zip(points) {
            let mut c = G1Projective::from(proof.commitment_to_polynomial.0);
            let w = proof.commitment_to_witness.0;
            c += w * point;
            g_multiplier += challenge * proof.evaluated_point;

            total_c += c * challenge;
            total_w += w * challenge;
        }
        total_c -= self.g * g_multiplier;

        let affine_total_w = G1Affine::from(-total_w);
        let affine_total_c = G1Affine::from(total_c);

        let pairing = dusk-bls12_381::multi_miller_loop(&[
            (&affine_total_w, &self.prepared_beta_h),
            (&affine_total_c, &self.prepared_h),
        ])
        .final_exponentiation();

        pairing == dusk-bls12_381::Gt::identity()
    }
}

/// Checks whether the polynomial we are committing to:
/// - Has zero degree
/// - Has a degree which is more than the max supported degree
///
///
/// Returns an error if any of the above conditions are true.
fn check_degree_is_within_bounds(max_degree: usize, poly_degree: usize) -> Result<(), Error> {
    if poly_degree == 0 {
        return Err(Error::PolynomialDegreeIsZero);
    }
    if poly_degree > max_degree {
        return Err(Error::PolynomialDegreeTooLarge);
    }
    Ok(())
}
#[cfg(test)]
mod test {
    use super::super::srs::*;
    use super::*;
    use merlin::Transcript;

    // Creates a proving key and verifier key based on a specified degree
    fn setup_test(degree: usize) -> (ProverKey, VerifierKey) {
        let srs = PublicParameters::setup(degree, &mut rand::thread_rng()).unwrap();
        srs.trim(degree).unwrap()
    }
    #[test]
    fn test_basic_commit() {
        let degree = 25;
        let (proving_key, verifier_key) = setup_test(degree);
        let point = Scalar::from(10);

        let poly = Polynomial::rand(degree, &mut rand::thread_rng());
        let value = poly.evaluate(&point);

        let proof = proving_key.open_single(&poly, &value, &point).unwrap();

        let ok = verifier_key.check(point, proof);
        assert!(ok);
    }
    #[test]
    fn test_batch_verification() {
        let degree = 25;
        let (proving_key, vk) = setup_test(degree);

        let point_a = Scalar::from(10);
        let point_b = Scalar::from(11);

        // Compute secret polynomial a
        let poly_a = Polynomial::rand(degree, &mut rand::thread_rng());
        let value_a = poly_a.evaluate(&point_a);
        let proof_a = proving_key
            .open_single(&poly_a, &value_a, &point_a)
            .unwrap();
        assert!(vk.check(point_a, proof_a));

        // Compute secret polynomial b
        let poly_b = Polynomial::rand(degree, &mut rand::thread_rng());
        let value_b = poly_b.evaluate(&point_b);
        let proof_b = proving_key
            .open_single(&poly_b, &value_b, &point_b)
            .unwrap();
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
        let max_degree = 27;
        let (proving_key, verifier_key) = setup_test(max_degree);
        let point = Scalar::from(10);

        // Prover's View
        let aggregated_proof = {
            // Compute secret polynomials and their evaluations
            let poly_a = Polynomial::rand(25, &mut rand::thread_rng());
            let poly_a_eval = poly_a.evaluate(&point);

            let poly_b = Polynomial::rand(26 + 1, &mut rand::thread_rng());
            let poly_b_eval = poly_b.evaluate(&point);

            let poly_c = Polynomial::rand(27, &mut rand::thread_rng());
            let poly_c_eval = poly_c.evaluate(&point);

            proving_key
                .open_multiple(
                    &[poly_a, poly_b, poly_c],
                    vec![poly_a_eval, poly_b_eval, poly_c_eval],
                    &point,
                    &mut Transcript::new(b"agg_flatten"),
                )
                .unwrap()
        };

        // Verifier's View
        let ok = {
            let flattened_proof = aggregated_proof.flatten(&mut Transcript::new(b"agg_flatten"));
            verifier_key.check(point, flattened_proof)
        };

        assert!(ok);
    }

    #[test]
    fn test_batch_with_aggregation() {
        let max_degree = 28;
        let (proving_key, verifier_key) = setup_test(max_degree);
        let point_a = Scalar::from(10);
        let point_b = Scalar::from(11);

        // Prover's View
        let (aggregated_proof, single_proof) = {
            // Compute secret polynomial and their evaluations
            let poly_a = Polynomial::rand(25, &mut rand::thread_rng());
            let poly_a_eval = poly_a.evaluate(&point_a);

            let poly_b = Polynomial::rand(26, &mut rand::thread_rng());
            let poly_b_eval = poly_b.evaluate(&point_a);

            let poly_c = Polynomial::rand(27, &mut rand::thread_rng());
            let poly_c_eval = poly_c.evaluate(&point_a);

            let poly_d = Polynomial::rand(28, &mut rand::thread_rng());
            let poly_d_eval = poly_d.evaluate(&point_b);

            let aggregated_proof = proving_key
                .open_multiple(
                    &[poly_a, poly_b, poly_c],
                    vec![poly_a_eval, poly_b_eval, poly_c_eval],
                    &point_a,
                    &mut Transcript::new(b"agg_batch"),
                )
                .unwrap();

            let single_proof = proving_key
                .open_single(&poly_d, &poly_d_eval, &point_b)
                .unwrap();

            (aggregated_proof, single_proof)
        };

        // Verifier's View
        let ok = {
            let mut transcript = Transcript::new(b"agg_batch");
            let flattened_proof = aggregated_proof.flatten(&mut transcript);

            verifier_key.batch_check(
                &[point_a, point_b],
                &[flattened_proof, single_proof],
                &mut transcript,
            )
        };

        assert!(ok);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn prover_key_serde_roundtrip() {
        use bincode;
        let prover_key = ProverKey {
            powers_of_g: vec![
                G1Affine::generator(),
                G1Affine::generator(),
                G1Affine::generator(),
                G1Affine::generator(),
                G1Affine::generator(),
                G1Affine::generator(),
            ],
        };
        let ser = bincode::serialize(&prover_key).unwrap();
        let deser: ProverKey = bincode::deserialize(&ser).unwrap();

        assert!(&prover_key.powers_of_g[..] == &deser.powers_of_g[..]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn verifier_key_serde_roundtrip() {
        use bincode;
        use dusk-bls12_381::G2Prepared;
        let g2_point = G2Affine::generator();
        let g2_prep_point = G2Prepared::from(g2_point);
        let g1_point = G1Affine::generator();

        let verifier_key = VerifierKey {
            g: g1_point,
            h: g2_point,
            beta_h: g2_point,
            prepared_h: g2_prep_point.clone(),
            prepared_beta_h: g2_prep_point,
        };
        let ser = bincode::serialize(&verifier_key).unwrap();
        let deser: VerifierKey = bincode::deserialize(&ser).unwrap();

        assert!(verifier_key.g == deser.g);
        assert!(verifier_key.h == deser.h);
        assert!(verifier_key.beta_h == deser.beta_h);
    }
}
