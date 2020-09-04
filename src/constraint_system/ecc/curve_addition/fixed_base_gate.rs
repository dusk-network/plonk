// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

use crate::constraint_system::StandardComposer;
use crate::constraint_system::Variable;
use dusk_bls12_381::Scalar;

#[derive(Debug, Clone, Copy)]
/// Contains all of the components needed to verify that a bit scalar multiplication was computed correctly
pub(crate) struct WnafRound {
    /// This is the accumulated x coordinate point that we wish to add (so far.. depends on where you are in the scalar mul)
    /// it is linked to the wnaf entry, so must not be revealed
    pub acc_x: Variable,
    /// This is the accumulated y coordinate
    pub acc_y: Variable,

    /// This is the wnaf accumulated entry
    /// For all intents and purposes, you can think of this as the secret bit
    pub accumulated_bit: Variable,

    /// This is the multiplication of x_\alpha * y_\alpha
    /// we need this as a distinct wire, so that the degree of the polynomial does not go over 4
    pub xy_alpha: Variable,
    /// This is the possible x co-ordinate of the wnaf point we are going to add
    /// Actual x-co-ordinate = b_i * x_\beta
    pub x_beta: Scalar,
    /// This is the possible y co-ordinate of the wnaf point we are going to add
    /// Actual y coordinate = (b_i)^2 [y_\beta -1] + 1
    pub y_beta: Scalar,
    /// This is the multiplication of x_\beta * y_\beta
    pub xy_beta: Scalar,
}

impl StandardComposer {
    /// Fixed group addition of a jubjub point
    pub(crate) fn fixed_group_add(&mut self, wnaf_round: WnafRound) {
        self.w_l.push(wnaf_round.acc_x);
        self.w_r.push(wnaf_round.acc_y);
        self.w_o.push(wnaf_round.xy_alpha);
        self.w_4.push(wnaf_round.accumulated_bit);

        self.q_l.push(wnaf_round.x_beta);
        self.q_r.push(wnaf_round.y_beta);

        self.q_c.push(wnaf_round.xy_beta);
        self.q_o.push(Scalar::zero());
        self.q_fixed_group_add.push(Scalar::one());
        self.q_variable_group_add.push(Scalar::zero());

        self.q_m.push(Scalar::zero());
        self.q_4.push(Scalar::zero());
        self.q_arith.push(Scalar::zero());
        self.q_range.push(Scalar::zero());
        self.q_logic.push(Scalar::zero());

        self.public_inputs.push(Scalar::zero());

        self.perm.add_variables_to_map(
            wnaf_round.acc_x,
            wnaf_round.acc_y,
            wnaf_round.xy_alpha,
            wnaf_round.accumulated_bit,
            self.n,
        );

        self.n += 1;
    }
}
