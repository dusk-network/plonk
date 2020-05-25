//!  This file will create the ladder for the implementation of the ECC gate.
//!  Given a point and a scalar, split into quads, the functions returns
//!  a new field element.

// TODO: REMOVE THE UNECESSARY FUCNTIONS WITHIN THIS LIBRARY
use crate::constraint_system::{StandardComposer, Variable};
use core::ops::Neg;
use dusk_bls12_381::Scalar;
use jubjub::Fr;
use jubjub::{AffinePoint, ExtendedPoint, GENERATOR};

pub struct LadderValues {
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
        let two = ExtendedPoint::from(GENERATOR) + ExtendedPoint::from(GENERATOR);
        let term = two + ExtendedPoint::from(GENERATOR);
        let three = AffinePoint::from(term);
        LadderValues {
            one,
            three,
            q_x_1: Fr::zero(),
            q_x_2: Fr::zero(),
            q_y_1: Fr::zero(),
            q_y_2: Fr::zero(),
        }
    }
}

pub fn fixed_base_ladder() -> [AffinePoint; 4] {
    let mut ladder = [GENERATOR; 4];
    let g = GENERATOR;

    let g2 = ExtendedPoint::from(GENERATOR) + ExtendedPoint::from(GENERATOR);
    let g_term = g2 + ExtendedPoint::from(GENERATOR);

    let g3 = AffinePoint::from(g_term);

    ladder[0] = g;
    ladder[1] = g3;
    ladder[2] = g.neg();
    ladder[3] = g3.neg();

    ladder
}

/// For the purpose of the fixed base add gate, we will be using
/// value of scalars written in the window NAF form. When a scalar w-NAF 
/// is evaluated as a w-NAF array, it can only contain values: 1, 3, -1 
/// or -3.
/// This calculation for the points within the 'fixed base ladder'
/// differs depending on the index of the w-NAF that we're evaluating.
/// The fixed generator point, g, becomes gi, based on the formula:
/// gi = 4^(n-i)*g. `n` here is the number of elements in the w-NAF
/// array, where the max is 256. `i` is the round that is currently
/// being evaluated; where `i` starts at `0` and goes up to n-1.
pub fn scalar_mul(scalar: Fr, composer: &mut StandardComposer) -> Variable {
    // Get scalar in correct format
    // [i8; 256]
    let mut wnaf_scalar = scalar.compute_windowed_naf(3u8).to_vec();
    wnaf_scalar.reverse();

    // This is where the accumulator is set.
    let mut t = Fr::zero();
    let b = ExtendedPoint::from(GENERATOR);
    let wnaf_len = wnaf_scalar.len();
    
    The initial values
    // The initial x and y values, aka the offset, differ depending on the 
    // the conditional sign of the scalar. This is either (4^n + 1) * g, or 
    // (4^n) * g.
    if scalar.is_even() {
        t = Fr::from((4 as usize).pow((wnaf_scalar.len() + 1) as u32) as u64);
    } else {
        t = Fr::from((4 as usize).pow(wnaf_scalar.len() as u32) as u64);
    }

    let mut accums: Vec<Fr> = vec![];

    // The initial accumulator values, aka the offset, differs depending on the 
    // the conditional sign of the scalar. This is either 1 or (1+1)/4^n. 
    let mut accum_0 = t;
    let mut accum_1 = t;
    accum_0.divn(((4 as usize).pow(wnaf_scalar.len() as u32)) as u32);
    accum_1.divn(
        (((4 as usize).pow((wnaf_scalar.len() - 1) as u32))
            + (wnaf_scalar[wnaf_scalar.len() - 1] as usize)) as u32,
    );

    accums.push(accum_0);
    accums.push(accum_1);

    // Using gi from the function description above, we compute 
    // -gi, 3gi & -3gi. 
    let mut mul_points: Vec<ExtendedPoint> = vec![];
    for i in wnaf_scalar.iter().enumerate() {
        let g_i = ExtendedPoint::from(GENERATOR)
            * Fr::from((4 as usize).pow((wnaf_scalar.len() - i.0) as u32) as u64);
        let g_i_neg = g_i.neg();
        let g_i_3 = g_i * Fr::from(3 as u64);
        let g_i_neg_3 = g_i_3.neg();

        let g_i_affine = AffinePoint::from(g_i);
        let g_i_3_affine = AffinePoint::from(g_i_3);
        let g_i_neg_affine = AffinePoint::from(g_i_neg);
        let g_i_3_neg_affine = AffinePoint::from(g_i_neg_3);

        // Now that we have 4 potential points, and thus 8 coordinates/
        // scalar, we need to choose which one we add to our current round.
        // 
        // If the actual value, at round i, is negative, then we need to select
        // from the negated points. If not, then we use the positive points.
        // If the value actual value, at round i, was 1 or -1, then we use 3 times 
        // the point. Otherwise, use the point itself.
        let point_to_add = match (*i.1 > 0i8, *i.1 < 0i8, *i.1 == 0i8) {
            (true, false, false) => {
                if *i.1 == 1i8 {
                    g_i_affine
                } else {
                    g_i_3_affine
                }
            }
            (false, true, false) => {
                if *i.1 == -1i8 {
                    g_i_neg_affine
                } else {
                    g_i_3_neg_affine
                }
            }
            (false, false, true) => AffinePoint::identity(),
            _ => unreachable!(),
        };

        if i.0 == 0 {
            mul_points.push(ExtendedPoint::from(point_to_add));
        } else {
            mul_points.push(ExtendedPoint::from(point_to_add) + mul_points[i.0 - 1]);
        }

        if i.0 > 1 {
            let accum = Fr::from(4 as u64) * accums[i.0 - 1]
                + Fr::from(wnaf_scalar[wnaf_scalar.len() - i.0] as u64);
            accums.push(accum);
        }
        
        // Here, the x-alpha of the point which is chosen to be added in
        // is set, as it will become the output wire programme memory.
        let mut x_alpha = Fr::zero();

        if *i.1 % 2 == 0 {
            x_alpha = Fr::from_bytes(&g_i_affine.get_x().to_bytes()).unwrap();
        } else {
            x_alpha = Fr::from_bytes(&g_i_3_affine.get_x().to_bytes()).unwrap();
        }

        // Depending on the round, or we call the different gates,
        // from the composer and push the wires to accordingly in 
        // the programme memory.
        if i.0 == 0 {
            // TODO: remove Fr unwraps
            composer.fixed_base_add_with_initial(
                Fr::from_bytes(&AffinePoint::from(mul_points[i.0]).get_x().to_bytes()).unwrap(),
                Fr::from_bytes(&AffinePoint::from(mul_points[i.0]).get_y().to_bytes()).unwrap(),
                x_alpha,
                accums[i.0],
            );
        } else if i.0 < wnaf_scalar.len() - 1 {
            composer.fixed_base_add(
                Fr::from_bytes(&AffinePoint::from(mul_points[i.0]).get_x().to_bytes()).unwrap(),
                Fr::from_bytes(&AffinePoint::from(mul_points[i.0]).get_y().to_bytes()).unwrap(),
                x_alpha,
                accums[i.0],
                256,
            );
        } else {
            let var_a = composer.add_jubjub_input(
                Fr::from_bytes(&AffinePoint::from(mul_points[i.0]).get_x().to_bytes()).unwrap(),
            );
            let var_b = composer.add_jubjub_input(
                Fr::from_bytes(&AffinePoint::from(mul_points[i.0]).get_y().to_bytes()).unwrap(),
            );
            let var_c = composer.add_jubjub_input(x_alpha);
            let var_d = composer.add_jubjub_input(accums[i.0]);
            composer.big_add_gate(
                var_a,
                var_b,
                var_c,
                var_d,
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
                Scalar::zero(),
            );
        }
    }

    composer.w_o[composer.w_o.len() - 1]
}

// Now that we have our scalar in the NAF form, we need to precompute our look up table.
// This is done to provide the potential add-in-x-coordinate's at each round. As only 1
// and 3 are possible, the ladder look up function will be a 2 bit output. The 2 resulting
// output coordinates, along with their negative y-coordinate counterparts, will be the
// 4 coordinates, which the add-in-x-coordinate is derived from.

#[test]
fn test_ladder() {
    let ladder = fixed_base_ladder();
    assert_eq!(ladder[0], GENERATOR);
    assert_eq!(
        ladder[1],
        AffinePoint::from(ExtendedPoint::from(GENERATOR) * Fr::from(3 as u64))
    );
}

#[test]
fn test_scalar_mul() {
    let mut composer = StandardComposer::default();
    let point = GENERATOR;
    let gen_x = point.get_x();
    let gen_y = point.get_y();
    let scalar = Fr::from(31 as u64);

    // TODO: what do we need to check?
    // assert_eq!(scalar_mul(scalar, &mut composer), 6749237362536748595030987654329305826145364798328171542537485058472526649593, 435472901526383203736325467483956216236323421376357876155393487519030193845 )
}
