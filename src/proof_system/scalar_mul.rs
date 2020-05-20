//!  This file will create the ladder for the implementation of the ECC gate.
//!  Given a point and a scalar, split into quads, the functions returns 
//!  a new field element.


use jubjub::Fr;
use jubjub::{AffinePoint, GENERATOR};

pub struct LadderValues{
    pub one: AffinePoint,
    pub three: AffinePoint,
    pub q_x_1: Fr,
    pub q_x_2: Fr,
    pub q_y_1: Fr,
    pub q_y_2: Fr,
}

impl Default for LadderValues {
    fn default() -> Self {
        let one = GENERATOR;
        let three = GENERATOR + GENERATOR + GENERATOR;



        LadderValues{
            one,
            three,
            q_x_1: Fr::zero(),
            q_x_2: Fr::zero(),
            q_y_1: Fr::zero(),
            q_y_2: Fr::zero(),
        }
    }
}

/// For the purpose of the fixed base add gate, we will be using 
/// the absolute value of scalars written in the window NAF form. 
/// This means, the quad input which the GENERATOR is multiplied
/// by can only be 1 or 3. 
pub fn fixed_base_ladder() -> [AffinePoint; 4] {
    let ladder = [GENERATOR; 4];
    let g = GENERATOR;

    let g2 = g + g;

    let g3 = 2g + g;

    ladder[0] = g;
    ladder[1] = 3g;
    ladder[2] = g.neg();
    ladder[3] = 3g.neg();


    ladder
}

pub fn round_GENERATOR(s: Fr) -> [AffinePoint; 2] {

}

pub fn scalar_mul(scalar: Fr, point: AffinePoint) -> Vec<(AffinePoint, AffinePoint)> {


// Get scalar in correct format
// [i8; 256]
let wnaf_scalar = scalar.compute_windowed_naf(3u8).to_vec();
        wnaf_scalar.reverse();
        // [point, 3 * point]
        let table = vec![GENERATOR, GENERATOR * wnaf_scalar::from(3 as u64)];
        for coeff in wnaf_scalar {
            let point_to_add = match (coeff > 0i8, coeff < 0i8, coeff == 0i8) {
                (true, false, false) => table[(coeff - 1) as usize],
                (false, true, false) => -table[(coeff.abs() - 1) as usize],
                (false, false, true) => AffinePoint::identity(),
                _ => unreachable!(),
            };
            
        }

// pub fn compute_initialiser(t: scalar, AffinePoint) -> AffinePoint {
        
    let mut t = 0;
    
    let b = GENERATOR;
    
    let initial = b * t;

    if scalar.is_even() {
        t = (4 as usize).pow((wnaf_scalar.len() + 1) as u32);    
    } else {
        t = (4 as usize).pow(wnaf_scalar.len() as u32);
    }

    let accums: Vec<usize> = vec![];

let accum_0 = t/((4 as usize).pow(wnaf_scalar.len() as u32));
let accum_1 = t/((4 as usize).pow(wnaf_scalar.len()-1)) + wnaf_scalar[wnaf_scalar.len()-1];

accums.push(accum_0);
accums.push(accum_1);

// pub fn compute_gi_muls(GENERATOR: AffinePoint, wnaf_scalar: Vec<u8>) -> Vec<(AffinePoint, AffinePoint)> {
    let mut gi_points: Vec<(AffinePoint, AffinePoint, AffinePoint, AffinePoint)> = vec![];
    for i in wnaf_scalar.iter().enumerate() {
        if i.0 == 0 {
            if scalar.is_even() {
                t = (4 as usize).pow((wnaf_scalar.len() + 1) as u32);    
            } else {
                t = (4 as usize).pow(wnaf_scalar.len() as u32);
            }
        }
        let g_i = AffinePoint::GENERATOR() * (4 as usize).pow((wnaf_scalar.len()-i.0) as u32);
        let g_i_neg = g_i.neg();
        let 3_g_i = 3 * g_i;
        let 3_g_i_neg = 3_g_i.neg();
        gi_points.push((g_i, g_i_neg, 3_g_i, 3_g_i_neg));

        if i.0 > 1 {
            let accum = 4*accums[i.0-1] + (wnaf_scalar[wnaf_scalar.len()-i.0] as usize);
            accums.push(accum);
        }

        let x_beta = g_i.get_x();
        let y_beta = g_i.get_y();
        let x_gamma = 3_g_i.get_x();
        let y_gamma = 3_g_i.get_y();
        let y_beta_neg = g_i_neg.get_y();
        let y_gamma_neg = 3_g_i_neg.get_y();
        
    }

    gi_points
}


// Now that we have our scalar in the NAF form, we need to precompute our look up table.
// This is done to provide the potential add-in-x-coordinate's at each round. As only 1
// and 3 are possible, the ladder look up function will be a 2 bit output. The 2 resulting
// output coordinates, along with their negative y-coordinate counterparts, will be the
// 4 coordinates, which the add-in-x-coordinate is derived from.


#[test]
fn test_ladder() {
    let ladder = fixed_base_ladder();
    assert_eq!(ladder[0], G1Affine::GENERATOR());
    assert_eq!(ladder[1], 3 * G1Affine::GENERATOR());
}

#[test]
fn test_scalar_mul() {
    let AffinePoint = point
    let AffinePoint.x = 9599346063476877603959045752087700136767736221838581394374215807052943515113 
    let AffinePoint.y = 2862382881649072392874176093266892593007690675622305830399263887872941817677
                        
    let scalar = Fr::from(31);
    
    
    assert_eq!(scalar_mul(scalar, point), 6749237362536748595030987654329305826145364798328171542537485058472526649593, 435472901526383203736325467483956216236323421376357876155393487519030193845 )


}