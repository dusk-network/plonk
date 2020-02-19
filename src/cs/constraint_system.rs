use algebra::fields::PrimeField;
// Design taken from bulletproofs
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
/// Stores the data for a specific wire in an arithmetic circuit
/// This data is the gate index and the type of wire
/// Left(1) signifies that this wire belongs to the first gate and is the left wire
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WireData {
    Left(usize),
    Right(usize),
    Output(usize),
}
