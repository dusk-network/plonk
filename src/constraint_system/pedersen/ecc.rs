use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use dusk_bls12_381::Scalar;

/// Fixed group add weierstrass
// #[derive(Debug, Clone, Copy)]
// pub struct FixedGroupAddQuad {
//     pub a: Variable,
//     pub b: Variable,
//     pub c: Variable,
//     pub d: Variable,
//     pub q_x_1: Scalar,
//     pub q_x_2: Scalar,
//     pub q_y_1: Scalar,
//     pub q_y_2: Scalar,
// }
/// Fixed group add with init wierstrass
// #[derive(Debug, Clone, Copy)]
// pub struct FixedGroupInitQuad {
//     pub q_x_1: Scalar,
//     pub q_x_2: Scalar,
//     pub q_y_1: Scalar,
//     pub q_y_2: Scalar,
// }

#[derive(Debug, Clone, Copy)]
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
        self.q_ecc.push(Scalar::zero());

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
    // Fixed group addition of a jubjub point
    // pub fn fixed_group_add(&mut self, add_quad: FixedGroupAddQuad) {
    //     self.w_l.push(add_quad.a);
    //     self.w_r.push(add_quad.b);
    //     self.w_o.push(add_quad.c);
    //     self.w_4.push(add_quad.d);

    //     self.q_l.push(add_quad.q_x_1);
    //     self.q_r.push(add_quad.q_x_2);
    //     self.q_o.push(add_quad.q_y_1);
    //     self.q_ecc.push(add_quad.q_y_2);

    //     self.q_m.push(Scalar::zero());
    //     self.q_c.push(Scalar::zero());
    //     self.q_4.push(Scalar::zero());
    //     self.q_arith.push(Scalar::zero());
    //     self.q_range.push(Scalar::zero());
    //     self.q_logic.push(Scalar::zero());

    //     self.public_inputs.push(Scalar::zero());

    //     self.perm
    //         .add_variables_to_map(add_quad.a, add_quad.b, add_quad.c, add_quad.d, self.n);

    //     self.n += 1;
    // }
    // Group add with init
    // pub fn fixed_group_add_init(&mut self, add_quad: FixedGroupAddQuad, init: FixedGroupInitQuad) {
    //     self.w_l.push(add_quad.a);
    //     self.w_r.push(add_quad.b);
    //     self.w_o.push(add_quad.c);
    //     self.w_4.push(add_quad.d);

    //     self.q_l.push(add_quad.q_x_1);
    //     self.q_r.push(add_quad.q_x_2);
    //     self.q_o.push(add_quad.q_y_1);
    //     self.q_ecc.push(add_quad.q_y_2);

    //     self.q_4.push(init.q_x_1);
    //     self.q_m.push(init.q_y_1);
    //     self.q_c.push(init.q_y_2);

    //     self.q_arith.push(Scalar::zero());
    //     self.q_range.push(Scalar::zero());
    //     self.q_logic.push(Scalar::zero());

    //     self.public_inputs.push(Scalar::zero());

    //     self.perm
    //         .add_variables_to_map(add_quad.a, add_quad.b, add_quad.c, add_quad.d, self.n);

    //     self.n += 1;
    // }
}
