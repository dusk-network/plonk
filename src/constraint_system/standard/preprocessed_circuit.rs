use crate::commitment_scheme::kzg10::Commitment;
use crate::fft::{Evaluations, Polynomial};
// Preprocessed circuit includes the commitment to the selector polynomials and the sigma polynomials
// for the standard plonk composer
pub struct PreProcessedCircuit {
    // The number of gates in the circuit
    pub n: usize,
    // Selector polynomial coefficients , their commitments and their 4n evaluation points
    pub selectors: Vec<(Polynomial, Commitment, Evaluations)>,

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
    pub fn qm_poly(&self) -> &Polynomial {
        &self.selectors[0].0
    }
    pub fn ql_poly(&self) -> &Polynomial {
        &self.selectors[1].0
    }
    pub fn qr_poly(&self) -> &Polynomial {
        &self.selectors[2].0
    }
    pub fn qo_poly(&self) -> &Polynomial {
        &self.selectors[3].0
    }
    pub fn qc_poly(&self) -> &Polynomial {
        &self.selectors[4].0
    }
    pub fn q4_poly(&self) -> &Polynomial {
        &self.selectors[5].0
    }
    pub fn qarith_poly(&self) -> &Polynomial {
        &self.selectors[6].0
    }
    pub fn qrange_poly(&self) -> &Polynomial {
        &self.selectors[7].0
    }
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
    pub fn qm_comm(&self) -> &Commitment {
        &self.selectors[0].1
    }
    pub fn ql_comm(&self) -> &Commitment {
        &self.selectors[1].1
    }
    pub fn qr_comm(&self) -> &Commitment {
        &self.selectors[2].1
    }
    pub fn qo_comm(&self) -> &Commitment {
        &self.selectors[3].1
    }
    pub fn qc_comm(&self) -> &Commitment {
        &self.selectors[4].1
    }
    pub fn q4_comm(&self) -> &Commitment {
        &self.selectors[5].1
    }
    pub fn qarith_comm(&self) -> &Commitment {
        &self.selectors[6].1
    }
    pub fn qrange_comm(&self) -> &Commitment {
        &self.selectors[7].1
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
    pub fn qm_eval_4n(&self) -> &Evaluations {
        &self.selectors[0].2
    }
    pub fn ql_eval_4n(&self) -> &Evaluations {
        &self.selectors[1].2
    }
    pub fn qr_eval_4n(&self) -> &Evaluations {
        &self.selectors[2].2
    }
    pub fn qo_eval_4n(&self) -> &Evaluations {
        &self.selectors[3].2
    }
    pub fn qc_eval_4n(&self) -> &Evaluations {
        &self.selectors[4].2
    }
    pub fn q4_eval_4n(&self) -> &Evaluations {
        &self.selectors[5].2
    }
    pub fn qarith_eval_4n(&self) -> &Evaluations {
        &self.selectors[6].2
    }
    pub fn qrange_eval_4n(&self) -> &Evaluations {
        &self.selectors[7].2
    }
    pub fn v_h_coset_4n(&self) -> &Evaluations {
        &self.v_h_coset_4n
    }
}
