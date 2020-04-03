use crate::constraint_system::widget::{
    ArithmeticWidget, LogicWidget, PermutationWidget, RangeWidget,
};
use crate::fft::Evaluations;

/// `PreProcessedCircuit` is a data structure that holds the commitments to
/// the selector and sigma polynomials.
///
/// By doing this, we can see the `PreProcessedCircuit` as a "circuit-shape descriptor"
/// since it only stores the commitments that describe the operations that we will perform
/// innside the circuit.
#[derive(Debug)]
pub struct PreProcessedCircuit {
    /// The number of gates in the circuit
    pub n: usize,
    /// Holds the polynomials, commitments and evaluations
    /// of all of the arithmetic-related gates.
    pub arithmetic: ArithmeticWidget,
    /// Holds the polynomials, commitments and evaluations
    /// of all of the range_constraint gate.
    pub range: RangeWidget,
    /// XXX: Add docs
    pub logic: LogicWidget,
    /// Holds the polynomials, commitments and evaluations
    /// related to the sigmas and also stores the linear
    /// evaluations.
    pub permutation: PermutationWidget,

    // Pre-processes the 4n Evaluations for the vanishing polynomial, so they do not
    // need to be computed at the proving stage.
    // Note: With this, we can combine all parts of the quotient polynomial in their evaluation phase and
    // divide by the quotient polynomial without having to IFFT
    pub(crate) v_h_coset_4n: Evaluations,
}
impl PreProcessedCircuit {
    pub(crate) fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}
