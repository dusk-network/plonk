use crate::cs::composer::StandardComposer;
use bls12_381::Scalar;
// Design taken from bulletproofs; although we should modify it to use iterators instead of vectors (zero-cost)
/// Represents a variable in a constraint system.

/// The value is a reference to the actual value that was added to the constraint system
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(pub(super) usize);

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct LinearCombination {
    pub(crate) terms: Vec<(Variable, Scalar)>,
}

impl LinearCombination {
    /// Taken from lovesh's fork of bulletproof
    /// Simplify linear combination by taking Variables common across terms and adding their corresponding scalars.
    /// Useful when linear combinations become large. Takes ownership of linear combination as this function is useful
    /// when memory is limited and the obvious action after this function call will be to free the memory held by the old linear combination
    pub fn simplify(self) -> Self {
        use std::collections::HashMap;
        // Build hashmap to hold unique variables with their values.
        let mut vars: HashMap<Variable, Scalar> = HashMap::new();

        let terms = self.terms;
        for (var, val) in terms {
            *vars.entry(var).or_insert(Scalar::zero()) += val;
        }

        let mut new_lc_terms = vec![];
        for (var, val) in vars {
            new_lc_terms.push((var, val));
        }
        Self {
            terms: new_lc_terms.into_iter().collect(),
        }
    }
}

impl From<Variable> for LinearCombination {
    fn from(v: Variable) -> Self {
        LinearCombination {
            terms: vec![(v, Scalar::one())],
        }
    }
}

use std::ops::{Add, Neg, Sub};

impl<L: Into<LinearCombination>> Add<L> for LinearCombination {
    type Output = Self;

    fn add(mut self, rhs: L) -> Self::Output {
        self.terms.extend(rhs.into().terms.iter().cloned());
        LinearCombination { terms: self.terms }
    }
}
impl Neg for LinearCombination {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for (_, s) in self.terms.iter_mut() {
            *s = -*s
        }
        self
    }
}

impl<L: Into<LinearCombination>> Sub<L> for LinearCombination {
    type Output = Self;

    fn sub(self, rhs: L) -> Self::Output {
        self + rhs.into().neg()
    }
}

impl Variable {
    pub fn mul(&self, composer: &mut StandardComposer, _rhs: Self) -> Self {
        composer.add_input(
            *composer.perm.variables.get(self).unwrap()
                * *composer.perm.variables.get(&_rhs).unwrap(),
        )
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
