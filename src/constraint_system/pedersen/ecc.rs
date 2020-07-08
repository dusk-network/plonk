use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use dusk_bls12_381::Scalar;

#[derive(Debug, Clone, Copy)]
/// Contains all of the components needed to verify that a bit scalar multiplication was computed correctly
pub struct WnafRound {
    /// This is the accumulated x coordinate point that we wish to add (so far.. depends on where you are in the scalar mul)
    /// it is linked to the wnaf entry, so must not be revealed
    pub acc_x: Variable,
    /// This is the accumulated y coordinate
    pub acc_y: Variable,

    /// This is the wnaf accumulated entry
    /// For all intents and purposes, you can think of this as the secret bit
    pub accumulated_bit: Variable,

    /// This is the multiplication of x_\alpha * y_\alpha * d
    /// we need this as a distinct wire, so that the degree of the polynomial does not go over 4
    pub xy_alpha: Variable,

    /// This is the possible x co-ordinate of the wnaf point we are going to add
    /// Actual x-co-ordinate = b_i * x_\beta
    pub x_beta: Scalar,
    /// This is the possible y co-ordinate of the wnaf point we are going to add
    /// Actual y coordinate = (b_i)^2 [y_\beta -1] + 1
    pub y_beta: Scalar,
}

impl StandardComposer {
    /// Fixed group addition of a jubjub point
    pub fn new_fixed_group_add(&mut self, add_quad: WnafRound) {
        self.w_l.push(add_quad.acc_x);
        self.w_r.push(add_quad.acc_y);
        self.w_o.push(add_quad.xy_alpha);
        self.w_4.push(add_quad.accumulated_bit);

        self.q_l.push(add_quad.x_beta);
        self.q_r.push(add_quad.y_beta);

        self.q_c.push(Scalar::zero());
        self.q_o.push(Scalar::zero());
        self.q_ecc.push(Scalar::one());

        self.q_m.push(Scalar::zero());
        self.q_4.push(Scalar::zero());
        self.q_arith.push(Scalar::zero());
        self.q_range.push(Scalar::zero());
        self.q_logic.push(Scalar::zero());

        self.public_inputs.push(Scalar::zero());

        self.perm.add_variables_to_map(
            add_quad.acc_x,
            add_quad.acc_y,
            add_quad.xy_alpha,
            add_quad.accumulated_bit,
            self.n,
        );

        self.n += 1;
    }

    /// Asserts that a witness point (Variable, Variable) is equal to a known public point
    pub fn assert_equal_point(
        &mut self,
        witness_point: (Variable, Variable),
        public_point: jubjub::AffinePoint,
    ) {
        let witness_x = witness_point.0;
        let witness_y = witness_point.1;

        self.constrain_to_constant(witness_x, Scalar::zero(), -public_point.get_x());
        self.constrain_to_constant(witness_y, Scalar::zero(), -public_point.get_y());
    }
}
