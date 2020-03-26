use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::widget::{ArithmeticWidget, RangeWidget};
use crate::fft::{Evaluations, Polynomial};
// Preprocessed circuit includes the commitment to the selector polynomials and the sigma polynomials
// for the standard plonk composer
pub struct PreProcessedCircuit {
    // The number of gates in the circuit
    pub n: usize,

    pub arithmetic: ArithmeticWidget,
    pub range: RangeWidget,

    // Sigma polynomials and their commitments
    pub left_sigma: (Polynomial, Commitment),
    pub right_sigma: (Polynomial, Commitment),
    pub out_sigma: (Polynomial, Commitment),
    pub fourth_sigma: (Polynomial, Commitment),

    // Preprocesses the 4n Evaluations for the vanishing polynomial, so they do not
    // need to be computed at the proving stage.
    // Note: With this, we can combine all parts of the quotient polynomial in their evaluation phase and
    // divide by the quotient polynomial without having to IFFT
    pub(crate) v_h_coset_4n: Evaluations,
}
impl PreProcessedCircuit {
    pub fn left_sigma_poly(&self) -> &Polynomial {
        &self.left_sigma.0
    }
    pub fn right_sigma_poly(&self) -> &Polynomial {
        &self.right_sigma.0
    }
    pub fn out_sigma_poly(&self) -> &Polynomial {
        &self.out_sigma.0
    }
    pub fn fourth_sigma_poly(&self) -> &Polynomial {
        &self.fourth_sigma.0
    }
    pub fn left_sigma_comm(&self) -> &Commitment {
        &self.left_sigma.1
    }
    pub fn right_sigma_comm(&self) -> &Commitment {
        &self.right_sigma.1
    }
    pub fn out_sigma_comm(&self) -> &Commitment {
        &self.out_sigma.1
    }
    pub fn fourth_sigma_comm(&self) -> &Commitment {
        &self.fourth_sigma.1
    }
    pub fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}
