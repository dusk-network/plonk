use crate::constraint_system::widget::{
    ArithmeticWidget, PermutationWidget, PublicInputWidget, RangeWidget,
};
use crate::fft::Evaluations;
// Preprocessed circuit includes the commitment to the selector polynomials and the sigma polynomials
// for the standard plonk composer
pub struct PreProcessedCircuit {
    // The number of gates in the circuit
    pub n: usize,

    pub arithmetic: ArithmeticWidget,
    pub range: RangeWidget,
    pub permutation: PermutationWidget,
    pub public_input: PublicInputWidget,

    // Preprocesses the 4n Evaluations for the vanishing polynomial, so they do not
    // need to be computed at the proving stage.
    // Note: With this, we can combine all parts of the quotient polynomial in their evaluation phase and
    // divide by the quotient polynomial without having to IFFT
    pub(crate) v_h_coset_4n: Evaluations,
}
impl PreProcessedCircuit {
    pub fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}
