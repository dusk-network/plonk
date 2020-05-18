// This file will contain the logic required
// to perform ECC operations in a PLONK
// circuit.

// For the scalar base operations we need to
// build a look up table, where we can find
// the values of particular indexes in 
#![allow(clippy::too_many_arguments)]
use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearisation_poly::ProofEvaluations;
use jubjub::Fq;
use jubjub::Fr;
use jubjub::AffinePoint;
use jubjub::AffineNielsPoint;

#[derive(Debug, Eq, PartialEq)]
pub struct ECCWidget {
    pub q_ecc: PreProcessedPolynomial,
}

fn basepoint_mul(&self, scalar: &fr) -> AffinePoint {
    let mut w_naf_scalar = scalar.compute_windowed_naf(3u8).to_vec();
    w_naf_scalar.reverse();

    //Set P = identity 
    let mut P = AffinePoint::identity();

    let mut wnaf_accum = Fr::zero();
    let four = Fr::from(4u64);

    // We iterate over the w_naf terms.
    for (i, wnaf_term) in w_naf_scalar.iter().enumerate() {
        wnaf_accum *= four;
        let wnaf_as_scalar = match (wnaf_term > 0i8, wnaf_term < 0i8, wnaf_term == 0i8) {
            (true, false, false) => Fr::from(wnaf_term as u64),
            (false, true, false) => Fr::zero(),
            (false, false, true) => -Fr::from(wnaf_term.abs() as u64),
            (_, _, _) => unreachable!(),
        };
        
        wnaf_accum += wnaf_as_scalar;

        match wnaf_as_scalar {
            Fr::zero() => {}
            Fr::one() => {
                P += P;
            }
            three => {
                let three = Fr::one() + Fr::one() + Fr::one();
                P = P + &three;
            };
        }  
    }

    P
    
    if i == 0 {

    } else {
        
    }
}

impl ScalarMulWidget {
    pub(crate) fn new(,
        q_ecc: (Polynomial, Commitment, Option<Evaluations>),
    ) -> ScalarMulWidget {
        ScalarMulWidget {
            q_ecc: PreProcessedPolynomial::new(q_ecc),
        }
    }
}

fn delta(f: Scalar) -> Scalar {
    let f_1 = f - Scalar::one();
    let f_2 = f - Scalar::from(2);
    let f_3 = f - Scalar::from(3);
    f * f_1 * f_2 * f_3
}

pub(crate) fn compute_quotient_i(
    &self,
    index: usize,
    ecc_consistency_challenge: &Scalar,
    w_l_i: &Scalar,
    w_l_i_next: &Scalar,
    w_r_i: &Scalar,
    w_r_i_next: &Scalar,
    w_o_i: &Scalar,
    w_o_i_next: &Scalar,
    w_4_i: &Scalar,
    w_4_i_next: &Scalar,
    q_o_i: &Scalar,
    q_ecc_i: &Scalar,
    q_1_i: &Scalar,
    q_2_i: &Scalar
) -> Scalar {

    let q_ecc_i = &self.q_ecc.evaluations.as_ref().unwrap()[index];
    let q_o_i = &self.q_o.evaluations.as_ref().unwrap()[index];
    
    let four = Scalar::from(4);
    let nine = Scalar::from(9);
    let one = Scalar::one();

    let kappa = ecc_consistency_challenge.square();
    let kappa_2 = kappa.square();
    let kappa_3 = kappa_2 * kappa;
    let kappa_4 = kappa_3 * kappa;
    let kappa_5 = kappa_4 * kappa;
    let kappa_6 = kappa_5 * kappa;
    let kappa_7 = kappa_6 * kappa;
    let kappa_8 = kappa_7 * kappa;
    let kappa_9 = kappa_8 * kappa;

    let acc_input = four * w_4_i;
    let accum = w_4_i_next - acc_input;

    let accum_sqr = accum.square();

    // Check that the accumulator consistency at the identity element
    // (accum - 1)(accum - 3)(accum + 1)(accum + 3) = 0 
    let a = accum_sqr - 9; 
    let b = accum_sqr - 1;
    let scalar_accum = a * b;
    let c_0 = delta(scalar_accum) * kappa;


    // To compute x-alpha, which is the x-coordinate that we're adding in at each round.
    let coeff_1 = accum_sqr * q_1_i;
    let x_alpha = coeff_1 + q_2_i;
    let w_o_i_next = x_alpha;
    
    // Consistency check of x_alpha for quotient.

    let c_1 = delta(w_o_i_next) * kappa_sq;

    // To compute the y-alpha, which is the y-coordinate that corresponds to the x which is added 
    // in each round then we use the formula below.
    let coeff_2 = w_o_i_next * q_o_i;
    let coeff_3 = coeff_2 + q_ecc_i;

    let y_alpha = coeff_3 * accum;
    
    // Check for consistency in the  x_value 

    let x_alpha_minus_x_one = w_o_i_next - w_l_i; 

    let 

    // Check for consistency in the y_value 

    let a_1 = 
}



 
   



    pub(crate) fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        a_next_eval: &Scalar,
        b_eval: &Scalar,
        b_next_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
        q_c_eval: &Scalar,
    ) -> Polynomial (){}


fn delta 