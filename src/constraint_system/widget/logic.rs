use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::constraint_system::standard::linearisation_poly::ProofEvaluations;
use crate::fft::{Evaluations, Polynomial};
use bls12_381::G1Affine;
use bls12_381::Scalar;

pub struct LogicWidget {
    pub q_c: PreProcessedPolynomial,
    pub q_logic: PreProcessedPolynomial,
}

impl LogicWidget {
    pub fn new(
        q_c: (Polynomial, Commitment, Option<Evaluations>),
        q_logic: (Polynomial, Commitment, Option<Evaluations>),
    ) -> LogicWidget {
        LogicWidget {
            q_logic: PreProcessedPolynomial::new(q_logic),
            q_c: PreProcessedPolynomial::new(q_c),
        }
    }

    pub fn compute_quotient_i(
        &self,
        index: usize,
        w_l_i: &Scalar,
        w_l_i_next: &Scalar,
        w_r_i: &Scalar,
        w_r_i_next: &Scalar,
        w_o_i: &Scalar,
        w_4_i: &Scalar,
        w_4_i_next: &Scalar,
    ) -> Scalar {
        let four = Scalar::from(4);

        let q_logic_i = &self.q_logic.evaluations.as_ref().unwrap()[index];
        let q_c_i = &self.q_c.evaluations.as_ref().unwrap()[index];

        let c_0 = (w_l_i_next - w_r_i_next) * w_o_i;
        let c_1 = delta(w_l_i_next - four * w_l_i);
        let c_2 = delta(w_r_i_next - four * w_r_i);
        let c_3 = delta(w_4_i_next - four * w_4_i);
        /*let c_4 = {
            let six = Scalar::from(6u64);
            let eighty_one = Scalar::from(81u64);
            let eighty_three = Scalar::from(83u64);
            let mut delta_sum = Scalar::zero();
            let mut delta_sq_sum = Scalar::zero();
            let mut T0 = Scalar::zero();
            let mut T1 = Scalar::zero();
            let mut T2 = Scalar::zero();
            let mut T3 = Scalar::zero();
            let mut T4 = Scalar::zero();
            let mut identity = Scalar::zero();
            // T0 = a
            T0 = w_l_i.double();
            T0 = T0.double();
            T0 = w_l_i_next - T0;
            // T1 = b
            T1 = w_r_i.double();
            T1 = T1.double();
            T1 = w_r_i_next - T1;
            // delta_sum = a + b
            delta_sum = T0 + T1;
            // T2 = a^2
            T2 = T0 * T0;
            // T3 = b^2
            T3 = T1 * T1;
            delta_sq_sum = T2 + T3;
            // identity = a^2 + b^2 + 2ab
            identity = delta_sum * delta_sum;
            // identity = 2ab
            identity -= delta_sq_sum;
            // identity = 2(ab - w)
            T4 = w_o_i.double();
            identity -= T4;
            // identity *= alpha; XXX: What happens with alphas now?
            // T4 = 4w
            T4 += T4;
            // T2 = a^2 - a
            T2 -= T0;
            // T0 = a^2 - 5a + 6
            T0 += T0;
            T0 += T0;
            T0 = T2 - T0;
            T0 += six;
            // identity = (identity + a(a - 1)(a - 2)(a - 3)) * alpha
            T0 *= T2;
            identity += T0;
            // identity *= alpha; XXX: What happens with alphas now?
            // T3 = b^2 - b
            T3 -= T1;
            // T1 = b^2 - 5b + 6
            T1 += T1;
            T1 += T1;
            T1 = T3 - T1;
            T1 += six;
            // identity = (identity + b(b - 1)(b - 2)(b - 3)) * alpha
            T1 *= T3;
            identity += T1;
            // identity *= alpha; XXX: What happens with alphas now?
            // T0 = 3(a + b)
            T0 = delta_sum + delta_sum;
            T0 += delta_sum;
            // T1 = 9(a + b)
            T1 = T0 + T0;
            T1 += T0;
            // delta_sum = 18(a + b)
            delta_sum = T1 + T1;
            // T1 = 81(a + b)
            T2 = delta_sum + delta_sum;
            T2 += T2;
            T1 += T2;
            // delta_squared_sum = 18(a^2 + b^2)
            T2 = delta_sq_sum + delta_sq_sum;
            T2 += delta_sq_sum;
            delta_sq_sum = T2 + T2;
            delta_sq_sum += T2;
            delta_sq_sum += delta_sq_sum;
            // delta_sum = w(4w - 18(a + b) + 81)
            delta_sum = T4 - delta_sum;
            delta_sum += eighty_one;
            delta_sum *= w_o_i;
            // T1 = 18(a^2 + b^2) - 81(a + b) + 83
            T1 = delta_sq_sum - T1;
            T1 += eighty_three;
            // delta_sum = w ( w ( 4w - 18(a + b) + 81) + 18(a^2 + b^2) - 81(a + b) + 83)
            delta_sum += T1;
            delta_sum *= w_o_i;
            // T2 = 3c
            T2 = w_4_i.double();
            T2 += T2;
            T2 = w_4_i_next - T2;
            T3 = T2 + T2;
            T2 += T3;
            // T3 = 9c
            T3 = T2 + T2;
            T3 += T2;
            // T3 = q_c * (9c - 3(a + b))
            T3 -= T0;
            T3 *= q_c_i;
            // T2 = 3c + 3(a + b) - 2 * delta_sum
            T2 += T0;
            delta_sum += delta_sum;
            T2 -= delta_sum;
            // T2 = T2 + T3
            T2 += T3;
            // identity = q_logic * alpha_base * (identity + T2)
            identity += T2;
            // identity *= alpha_base;
            identity *= q_logic_i;
            identity
        };
        c_4*/
        q_logic_i * (c_0 + c_1 + c_2 + c_3)
    }

    pub fn compute_linearisation(
        &self,
        a_eval: &Scalar,
        a_next_eval: &Scalar,
        b_eval: &Scalar,
        b_next_eval: &Scalar,
        c_eval: &Scalar,
        d_eval: &Scalar,
        d_next_eval: &Scalar,
        q_c_eval: &Scalar,
        q_logic_eval: &Scalar,
    ) -> Polynomial {
        let four = Scalar::from(4);

        let q_logic_poly = &self.q_logic.polynomial;

        let c_0 = (a_next_eval - b_next_eval) * c_eval;
        let c_1 = delta(a_next_eval - four * a_eval);
        let c_2 = delta(b_next_eval - four * b_eval);
        let c_3 = delta(d_next_eval - four * d_eval);
        /*let c_4 = {
            let six = Scalar::from(6u64);
            let eighty_one = Scalar::from(81u64);
            let eighty_three = Scalar::from(83u64);
            let mut delta_sum = Scalar::zero();
            let mut delta_sq_sum = Scalar::zero();
            let mut T0 = Scalar::zero();
            let mut T1 = Scalar::zero();
            let mut T2 = Scalar::zero();
            let mut T3 = Scalar::zero();
            let mut T4 = Scalar::zero();
            let mut identity = Scalar::zero();
            // T0 = a
            T0 = a_eval.double();
            T0 = T0.double();
            T0 = a_next_eval - T0;
            // T1 = b
            T1 = b_eval.double();
            T1 = T1.double();
            T1 = b_next_eval - T1;
            // delta_sum = a + b
            delta_sum = T0 + T1;
            // T2 = a^2
            T2 = T0 * T0;
            // T3 = b^2
            T3 = T1 * T1;
            delta_sq_sum = T2 + T3;
            // identity = a^2 + b^2 + 2ab
            identity = delta_sum * delta_sum;
            // identity = 2ab
            identity -= delta_sq_sum;
            // identity = 2(ab - w)
            T4 = c_eval.double();
            identity -= T4;
            // identity *= alpha; XXX: What happens with alphas now?
            // T4 = 4w
            T4 += T4;
            // T2 = a^2 - a
            T2 -= T0;
            // T0 = a^2 - 5a + 6
            T0 += T0;
            T0 += T0;
            T0 = T2 - T0;
            T0 += six;
            // identity = (identity + a(a - 1)(a - 2)(a - 3)) * alpha
            T0 *= T2;
            identity += T0;
            // identity *= alpha; XXX: What happens with alphas now?
            // T3 = b^2 - b
            T3 -= T1;
            // T1 = b^2 - 5b + 6
            T1 += T1;
            T1 += T1;
            T1 = T3 - T1;
            T1 += six;
            // identity = (identity + b(b - 1)(b - 2)(b - 3)) * alpha
            T1 *= T3;
            identity += T1;
            // identity *= alpha; XXX: What happens with alphas now?
            // T0 = 3(a + b)
            T0 = delta_sum + delta_sum;
            T0 += delta_sum;
            // T1 = 9(a + b)
            T1 = T0 + T0;
            T1 += T0;
            // delta_sum = 18(a + b)
            delta_sum = T1 + T1;
            // T1 = 81(a + b)
            T2 = delta_sum + delta_sum;
            T2 += T2;
            T1 += T2;
            // delta_squared_sum = 18(a^2 + b^2)
            T2 = delta_sq_sum + delta_sq_sum;
            T2 += delta_sq_sum;
            delta_sq_sum = T2 + T2;
            delta_sq_sum += T2;
            delta_sq_sum += delta_sq_sum;
            // delta_sum = w(4w - 18(a + b) + 81)
            delta_sum = T4 - delta_sum;
            delta_sum += eighty_one;
            delta_sum *= c_eval;
            // T1 = 18(a^2 + b^2) - 81(a + b) + 83
            T1 = delta_sq_sum - T1;
            T1 += eighty_three;
            // delta_sum = w ( w ( 4w - 18(a + b) + 81) + 18(a^2 + b^2) - 81(a + b) + 83)
            delta_sum += T1;
            delta_sum *= c_eval;
            // T2 = 3c
            T2 = d_eval.double();
            T2 += T2;
            T2 = d_next_eval - T2;
            T3 = T2 + T2;
            T2 += T3;
            // T3 = 9c
            T3 = T2 + T2;
            T3 += T2;
            // T3 = q_c * (9c - 3(a + b))
            T3 -= T0;
            T3 *= q_c_eval;
            // T2 = 3c + 3(a + b) - 2 * delta_sum
            T2 += T0;
            delta_sum += delta_sum;
            T2 -= delta_sum;
            // T2 = T2 + T3
            T2 += T3;
            // identity = q_logic * alpha_base * (identity + T2)
            identity += T2;
            // identity *= alpha_base;
            identity *= q_logic_eval;
            identity
        };
        // XXX: Review
        q_logic_poly * &c_4*/

        q_logic_poly * &(c_0 + c_1 + c_2 + c_3)
    }

    pub fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let four = Scalar::from(4);

        let c_0 = (evaluations.a_next_eval - evaluations.b_next_eval) * evaluations.c_eval;
        let c_1 = delta(evaluations.a_next_eval - four * evaluations.a_eval);
        let c_2 = delta(evaluations.b_next_eval - four * evaluations.b_eval);
        let c_3 = delta(evaluations.d_next_eval - four * evaluations.d_eval);
        /*let c_4 = {
            let six = Scalar::from(6u64);
            let eighty_one = Scalar::from(81u64);
            let eighty_three = Scalar::from(83u64);
            let mut delta_sum = Scalar::zero();
            let mut delta_sq_sum = Scalar::zero();
            let mut T0 = Scalar::zero();
            let mut T1 = Scalar::zero();
            let mut T2 = Scalar::zero();
            let mut T3 = Scalar::zero();
            let mut T4 = Scalar::zero();
            let mut identity = Scalar::zero();
            // T0 = a
            T0 = evaluations.a_eval.double();
            T0 = T0.double();
            T0 = evaluations.a_next_eval - T0;
            // T1 = b
            T1 = evaluations.b_eval.double();
            T1 = T1.double();
            T1 = evaluations.b_next_eval - T1;
            // delta_sum = a + b
            delta_sum = T0 + T1;
            // T2 = a^2
            T2 = T0 * T0;
            // T3 = b^2
            T3 = T1 * T1;
            delta_sq_sum = T2 + T3;
            // identity = a^2 + b^2 + 2ab
            identity = delta_sum * delta_sum;
            // identity = 2ab
            identity -= delta_sq_sum;
            // identity = 2(ab - w)
            T4 = evaluations.c_eval.double();
            identity -= T4;
            // identity *= alpha; XXX: What happens with alphas now?
            // T4 = 4w
            T4 += T4;
            // T2 = a^2 - a
            T2 -= T0;
            // T0 = a^2 - 5a + 6
            T0 += T0;
            T0 += T0;
            T0 = T2 - T0;
            T0 += six;
            // identity = (identity + a(a - 1)(a - 2)(a - 3)) * alpha
            T0 *= T2;
            identity += T0;
            // identity *= alpha; XXX: What happens with alphas now?
            // T3 = b^2 - b
            T3 -= T1;
            // T1 = b^2 - 5b + 6
            T1 += T1;
            T1 += T1;
            T1 = T3 - T1;
            T1 += six;
            // identity = (identity + b(b - 1)(b - 2)(b - 3)) * alpha
            T1 *= T3;
            identity += T1;
            // identity *= alpha; XXX: What happens with alphas now?
            // T0 = 3(a + b)
            T0 = delta_sum + delta_sum;
            T0 += delta_sum;
            // T1 = 9(a + b)
            T1 = T0 + T0;
            T1 += T0;
            // delta_sum = 18(a + b)
            delta_sum = T1 + T1;
            // T1 = 81(a + b)
            T2 = delta_sum + delta_sum;
            T2 += T2;
            T1 += T2;
            // delta_squared_sum = 18(a^2 + b^2)
            T2 = delta_sq_sum + delta_sq_sum;
            T2 += delta_sq_sum;
            delta_sq_sum = T2 + T2;
            delta_sq_sum += T2;
            delta_sq_sum += delta_sq_sum;
            // delta_sum = w(4w - 18(a + b) + 81)
            delta_sum = T4 - delta_sum;
            delta_sum += eighty_one;
            delta_sum *= evaluations.c_eval;
            // T1 = 18(a^2 + b^2) - 81(a + b) + 83
            T1 = delta_sq_sum - T1;
            T1 += eighty_three;
            // delta_sum = w ( w ( 4w - 18(a + b) + 81) + 18(a^2 + b^2) - 81(a + b) + 83)
            delta_sum += T1;
            delta_sum *= evaluations.c_eval;
            // T2 = 3c
            T2 = evaluations.d_eval.double();
            T2 += T2;
            T2 = evaluations.d_next_eval - T2;
            T3 = T2 + T2;
            T2 += T3;
            // T3 = 9c
            T3 = T2 + T2;
            T3 += T2;
            // T3 = q_c * (9c - 3(a + b))
            T3 -= T0;
            T3 *= evaluations.q_c_eval;
            // T2 = 3c + 3(a + b) - 2 * delta_sum
            T2 += T0;
            delta_sum += delta_sum;
            T2 -= delta_sum;
            // T2 = T2 + T3
            T2 += T3;
            // identity = q_logic * alpha_base * (identity + T2)
            identity += T2;
            // identity *= alpha_base;
            identity *= evaluations.q_logic_eval;
            identity
        };*/
        scalars.push(c_0 + c_1 + c_2 + c_3 /*+ c_4*/);
        points.push(self.q_logic.commitment.0);
    }
}

// Computes f(f-1)(f-2)(f-3)
fn delta(f: Scalar) -> Scalar {
    let f_1 = f - Scalar::one();
    let f_2 = f - Scalar::from(2);
    let f_3 = f - Scalar::from(3);
    f * f_1 * f_2 * f_3
}
