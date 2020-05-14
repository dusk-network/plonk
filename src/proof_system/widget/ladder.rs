//!  This file will create the ladder for the implementation of the ECC gate.
//!  Given a point and a scalar, split into quads, the functions returns 
//!  a new field element.


use dusk_bls12_381::G1Affine;
use dusk_bls12_381::Scalar;

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





#[test]
fn test_ladder() {
    let ladder = fixed_base_ladder();
    assert_eq!(ladder[0], G1Affine::generator());
    assert_eq!(ladder[1], 3 * G1Affine::generator());
}

