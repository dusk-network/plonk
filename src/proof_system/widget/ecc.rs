// This file will contain the logic required
// to perform ECC operations in a PLONK
// circuit.

// For the scalar base operations we need to
// build a look up table, where we can find
// the values of particular indexes in 

use super::PreProcessedPolynomial;
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

pub(crate) fn compute_quotient_i(
    &self,
    w_l_i: &Scalar,
    w_r_i: &Scalar,
    w_o_i: &Scalar,
    w_4_i: &Scalar,
    w_4_i_next: &Scalar,
) -> Scalar {
    let four = Scalar::from(4)

    let accumulator

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
    ) -> Polynomial {