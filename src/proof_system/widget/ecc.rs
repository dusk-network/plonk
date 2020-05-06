// This file will contain the logic required
// to perform ECC operations in a PLONK
// circuit.

// For the scalar base operations we need to
// build a look up table, where we can find
// the values of particular indexes in 

use jubjub::Fq;
use jubjub::Fr;
use jubjub::AffinePoint;
use jubjub::AffineNielsPoint;



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
            (false, false, tr
                ue) => -Fr::from(wnaf_term.abs() as u64),
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


