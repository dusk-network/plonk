use crate::commitment_scheme::kzg10::Commitment;
use crate::proof_system::linearisation_poly::ProofEvaluations;
use dusk_bls12_381::Scalar;
use merlin::Transcript;
use std::collections::HashMap;
/// Challenges represent all of the possible challenges that can be generated in PLONK
/// Defines all of the possible challenges in PLONK
/// This serves as documentation for what the challenges are used for
#[derive(Hash, PartialEq, Eq, Copy, Clone, Debug)]
pub(crate) enum Challenges {
    /// Used in the Quotient polynomial
    Alpha,
    /// Used in the Permutation polynomial
    Beta,
    /// Used in the Permutation polynomial
    Gamma,
    /// Used in the range widget to separate range identities
    RangeSeparation,
    /// Used in the logic widget to separate logic identities
    LogicSeparation,
    /// Evaluation challenge; used to evaluate a specified polynomial in the KZG10 scheme
    Evaluation,
    /// Aggregation challenge used in the KZG10 scheme
    Aggregation,
    /// Shifted aggregation challenge used in the KZG10 scheme
    ShiftedAggregation,
    /// Batch challenge used in the KZG10 scheme
    Batch,
}

impl Challenges {
    fn to_string(self) -> &'static [u8] {
        match self {
            Challenges::Alpha => b"alpha",
            Challenges::Beta => b"beta",
            Challenges::Gamma => b"gamma",
            Challenges::RangeSeparation => b"range",
            Challenges::LogicSeparation => b"logic",
            Challenges::Evaluation => b"evaluation",
            Challenges::Aggregation => b"agg",
            Challenges::ShiftedAggregation => b"shifted agg",
            Challenges::Batch => b"batch",
        }
    }
}
/// Evaluations represents all possible polynomials that can be evaluated in PLONK
/// Shifted denotes the polynomial being evaluated at at the evaluation challenge multiplied by the group generator `root of unity`
pub(crate) enum Evaluations {
    /// Quotient polynomial
    Quotient,
    /// Polynomial Representing the left wire values
    LeftWitness,
    ShiftedLeftWitness,
    /// Polynomial Representing the right wire values
    RightWitness,
    ShiftedRightWitness,
    /// Polynomial Representing the output wire values
    OutWitness,
    /// Polynomial Representing the fourth advice wire values
    FourthWitness,
    ShiftedFourthWitness,
    /// Polynomial representing the Copy Permutations for the left wire values
    LeftSigma,
    /// Polynomial representing the Copy Permutations for the right wire values
    RightSigma,
    /// Polynomial representing the Copy Permutations for the output wire values
    OutSigma,
    /// Polynomial representing the Arithmetic selector polynomial
    SelectorArithmetic,
    /// Polynomial representing the Arithmetic output polynomial
    SelectorOutput,
    /// Polynomial representing the permutation argument
    Permutation,
    /// Polynomial representing the lineariser
    Linearisation,
}

impl Evaluations {
    fn to_string(&self) -> &'static [u8] {
        match self {
            Evaluations::Quotient => b"quotient eval",
            Evaluations::LeftWitness => b"left witness eval",
            Evaluations::ShiftedLeftWitness => b"shifted left witness eval",
            Evaluations::RightWitness => b"right witness eval",
            Evaluations::ShiftedRightWitness => b"shifted right witness eval",
            Evaluations::OutWitness => b"out witness eval",
            Evaluations::FourthWitness => b"fourth witness eval",
            Evaluations::ShiftedFourthWitness => b"shifted fourth witness eval",
            Evaluations::LeftSigma => b"left sigma eval",
            Evaluations::RightSigma => b"right sigma eval",
            Evaluations::OutSigma => b"out sigma eval",
            Evaluations::SelectorArithmetic => b"selector arith eval",
            Evaluations::SelectorOutput => b"selector output eval",
            Evaluations::Permutation => b"permutation eval",
            Evaluations::Linearisation => b"linearisation eval",
        }
    }
}

/// Commitments represent all of the possible polynomials that are committed to in PLONK
/// XXX: QuotientPoly1 can be renamed better
#[derive(Hash, PartialEq, Eq)]
pub(crate) enum Commitments {
    /// Commitment to the Polynomial Representing the left wire values
    LeftWitness,
    /// Commitment to the Polynomial Representing the right wire values
    RightWitness,
    /// Commitment to the Polynomial Representing the output wire values
    OutWitness,
    /// Commitment to the Polynomial Representing the fourth advice wire values
    FourthWitness,
    /// Commitment to the Permutation polynomial
    Permutation,
    /// Commitment to the first n coefficients of the Quotient polynomial
    QuotientPoly1,
    /// Commitment to the second n coefficients of the Quotient polynomial
    QuotientPoly2,
    /// Commitment to the third n coefficients of the Quotient polynomial
    QuotientPoly3,
    /// Commitment to the fourth n coefficients of the Quotient polynomial
    QuotientPoly4,
    /// Commitment to the Opening Polynomial used in the commitment scheme
    /// The Proof is for an opening at the evaluation challenge `z`
    Opening,
    /// Commitment to the Shifted Opening Polynomial used in the commitment scheme
    /// The Proof is for an opening at the point `z * root of unity`
    ShiftedOpening,
}

impl Commitments {
    fn to_string(&self) -> &'static [u8] {
        match self {
            Commitments::LeftWitness => b"w_l",
            Commitments::RightWitness => b"w_r",
            Commitments::OutWitness => b"w_o",
            Commitments::FourthWitness => b"w_4",
            Commitments::Permutation => b"permuatation",
            Commitments::QuotientPoly1 => b"quotient 1",
            Commitments::QuotientPoly2 => b"quotient 2",
            Commitments::QuotientPoly3 => b"quotient 3",
            Commitments::QuotientPoly4 => b"quotient 4",
            Commitments::Opening => b"opening",
            Commitments::ShiftedOpening => b"shifted opening",
        }
    }
}

/// An abstraction over the transcript to cache challenges
pub struct Challenger {
    pub(crate) transcript: Transcript,
    cached_challenges: HashMap<Challenges, Scalar>,
}

impl Challenger {
    /// Generates a random challenge and caches it into the map
    pub(crate) fn compute_challenge(&mut self, label: Challenges) -> Scalar {
        // First check if we have computed this challenge before.
        let option_challenge = self.cached_challenges.get(&label);
        if option_challenge.is_none() {
            let challenge = self.squeeze_challenge(label);
            self.cached_challenges.insert(label, challenge);
        };
        self.cached_challenges[&label]
    }
    /// Squeeze a new challenge from the transcript
    fn squeeze_challenge(&mut self, label: Challenges) -> Scalar {
        let mut buf = [0u8; 64];
        self.transcript.challenge_bytes(label.to_string(), &mut buf);
        Scalar::from_bytes_wide(&buf)
    }
    /// Returns a challenge from the cache using the label as a key
    pub(crate) fn cached_challenge(&self, label: Challenges) -> Scalar {
        *self.cached_challenges.get(&label).unwrap()
    }
    /// Adds a commitment to the transcript
    pub(crate) fn append_commitment(&mut self, label: Commitments, comm: &Commitment) {
        self.transcript
            .append_message(label.to_string(), &comm.0.to_compressed());
    }
    /// Appends the challenge which we have already generated
    /// to the transcript
    pub(crate) fn append_challenge(&mut self, label: Challenges) {
        // Fetch challenge from cache
        let challenge = self.cached_challenges.get(&label).unwrap();

        self.transcript
            .append_message(label.to_string(), &challenge.to_bytes())
    }
    /// Appends a scalar to the transcript with a given label
    pub(crate) fn append_scalar(&mut self, label: Evaluations, scalar: &Scalar) {
        self.transcript
            .append_message(label.to_string(), &scalar.to_bytes())
    }
    /// Appends the evaluations to the transcript
    pub(crate) fn append_evaluations(&mut self, evaluations: &ProofEvaluations) {
        self.append_scalar(Evaluations::LeftWitness, &evaluations.a_eval);
        self.append_scalar(Evaluations::RightWitness, &evaluations.b_eval);
        self.append_scalar(Evaluations::OutWitness, &evaluations.c_eval);
        self.append_scalar(Evaluations::FourthWitness, &evaluations.d_eval);
        self.append_scalar(Evaluations::ShiftedLeftWitness, &evaluations.a_next_eval);
        self.append_scalar(Evaluations::ShiftedRightWitness, &evaluations.b_next_eval);
        self.append_scalar(Evaluations::ShiftedFourthWitness, &evaluations.d_next_eval);
        self.append_scalar(Evaluations::LeftSigma, &evaluations.left_sigma_eval);
        self.append_scalar(Evaluations::RightSigma, &evaluations.right_sigma_eval);
        self.append_scalar(Evaluations::OutSigma, &evaluations.out_sigma_eval);
        self.append_scalar(Evaluations::SelectorArithmetic, &evaluations.q_arith_eval);
        self.append_scalar(Evaluations::SelectorOutput, &evaluations.q_c_eval);
        self.append_scalar(Evaluations::Permutation, &evaluations.perm_eval);
        self.append_scalar(Evaluations::Linearisation, &evaluations.lin_poly_eval);
    }
}

/// Converts a Transcript to a Challenger object
/// This is safe to use if the transcript is preprocessed
/// because the preprocessing stage, does not produce any challenges
impl From<Transcript> for Challenger {
    fn from(t: Transcript) -> Challenger {
        Challenger {
            transcript: t,
            cached_challenges: HashMap::new(),
        }
    }
}
