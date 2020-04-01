use crate::commitment_scheme::kzg10::Commitment;
use crate::fft::{Evaluations, Polynomial};

pub mod arithmetic;
pub mod logic;
pub mod permutation;
pub mod range;

pub use arithmetic::ArithmeticWidget;
pub use logic::LogicWidget;
pub use permutation::PermutationWidget;
pub use range::RangeWidget;

pub struct PreProcessedPolynomial {
    pub(crate) polynomial: Polynomial,
    pub(crate) commitment: Commitment,
    pub(crate) evaluations: Option<Evaluations>,
}

impl PreProcessedPolynomial {
    pub fn new(t: (Polynomial, Commitment, Option<Evaluations>)) -> PreProcessedPolynomial {
        PreProcessedPolynomial {
            polynomial: t.0,
            commitment: t.1,
            evaluations: t.2,
        }
    }
}
