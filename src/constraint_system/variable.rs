use bls12_381::Scalar;

/// The value is a reference to the actual value that was added to the constraint system
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(pub(crate) usize);

impl Into<(Scalar, Variable)> for Variable {
    fn into(self) -> (Scalar, Variable) {
        (Scalar::one(), self)
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
    Fourth(usize),
}
