//!  This file will create the ladder for the implementation of the ECC gate.
//!  Given a point and a scalar, split into quads, the functions returns 
//!  a new field element.


use dusk_bls12_381::G1Affine;
use dusk_bls12_381::Scalar;
use jubjub::Fr;
use jubjub::AffinePoint;

pub struct LadderValues{
    pub one: G1Affine,
    pub three: G1Affine,
    pub q_x_1: Scalar,
    pub q_x_2: Scalar,
    pub q_y_1: Scalar,
    pub q_y_2: Scalar,
}

impl Default for LadderValues {
    pub fn default() -> Self {
        let one = G1Affine::generator();
            let three = G1Affine::generator() * 3;



        LadderValues{
            one,
            three,
        }
    }
}

pub fn round_generator(s: Fr) -> [G1Affine; 2] {



/// For the purpose of the fixed base add gate, we will be using 
/// the absolute value of scalars written in the window NAF form. 
/// This means, the quad input which the generator is multiplied
/// by can only be 1 or 3. 
pub fn fixed_base_ladder() -> [G1Affine; 2] {
    let ladder = [G1Affine::generator(); 2];
    let g = G1Affine::generator();

    let 2g = g.double();

    let 3g = 2g + g;

    ladder[1] = 3g;


    ladder
}

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
        
    }
}


pub fn compute_initialiser(t: scalar, AffinePoint) -> AffinePoint {
        
    let mut t = 0;
    if scalar.is_even() {
        t = 4**wnaf_scalar.length() + 1;    
    } else {
        t = 4**wnaf_scalar.length();
}
    let b = AffinePoint
    
    inital_point = b * t 

    inital_point,
}

let mut t = 0;
if scalar.is_even() {
    t = 4**wnaf_scalar.length() + 1;
} else {
    t = 4**wnaf_scalar.length();
}

let accum_0 = t/(4**wnaf_scalar.length());
let accum_1 = t/(4**wnaf_scalar.length()-1) + wnaf_scalar[wnaf_scalar.length()-1];

pub fn compute_gi_muls(generator: AffinePoint, wnaf_scalar: Vec<u8>) -> Vec<(AffinePoint, AffinePoint)> {
    let mut gi_points: Vec<(AffinePoint, AffinePoint)> = vec![];
    for i in wnaf_scalar.iter().enumerate() {
        let g_i = generator * 4**wnaf_scalar.length()-i;
        let 3_g_i = 3*g_i;
        gi_points.push((g_i, 3_g_i));
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
    assert_eq!(ladder[0], G1Affine::generator());
    assert_eq!(ladder[1], 3 * G1Affine::generator());
}

