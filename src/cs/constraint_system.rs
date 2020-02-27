use algebra::fields::PrimeField;
// Design taken from bulletproofs; although we should modify it to use iterators instead of vectors (zero-cost)
/// Represents a variable in a constraint system.
/// The value is a reference to the actual value that was added to the constraint system
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(pub(super) usize);

#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct LinearCombination<F: PrimeField> {
    pub(crate) terms: Vec<(Variable, F)>,
}

impl<F: PrimeField> LinearCombination<F> {
    // Simplifies a linear combination expression
    fn simplify(&mut self) {
        todo!()
    }
}

impl<F: PrimeField> From<Variable> for LinearCombination<F> {
    fn from(v: Variable) -> Self {
        LinearCombination {
            terms: vec![(v, F::one())],
        }
    }
}

use std::ops::{Add, Neg, Sub};

impl<F: PrimeField, L: Into<LinearCombination<F>>> Add<L> for LinearCombination<F> {
    type Output = Self;

    fn add(mut self, rhs: L) -> Self::Output {
        self.terms.extend(rhs.into().terms.iter().cloned());
        LinearCombination { terms: self.terms }
    }
}
impl<F: PrimeField> Neg for LinearCombination<F> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for (_, s) in self.terms.iter_mut() {
            *s = -*s
        }
        self
    }
}

impl<F: PrimeField, L: Into<LinearCombination<F>>> Sub<L> for LinearCombination<F> {
    type Output = Self;

    fn sub(self, rhs: L) -> Self::Output {
        self + rhs.into().neg()
    }
}

/// Stores the data for a specific wire in an arithmetic circuit
/// This data is the gate index and the type of wire
/// Left(1) signifies that this wire belongs to the first gate and is the left wire
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WireData {
    Left(usize),
    Right(usize),
    Output(usize),
}
