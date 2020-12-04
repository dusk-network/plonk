// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::multiset::MultiSet;
use dusk_plonk::bls12_381::BlsScalar;

pub struct WitnessTable3Arity {
    pub f_1: MultiSet,
    pub f_2: MultiSet,
    pub f_3: MultiSet,
}

pub struct WitnessTable4Arity {
    pub f_1: MultiSet,
    pub f_2: MultiSet,
    pub f_3: MultiSet,
    pub f_4: MultiSet,
}

/*
impl WitnessTable {

    pub from_wire_values(a: Vec<Variable>, b: Vec<Variable>, c: Vec<Variable>, d: Vec<Option<Vec>>) -> f: Vec![Variable] {

        // Build a corresponding table out the a and b inputs of the
        // same nature, to the one inputted.
        let f_table = a
            .iter()
            .zip(b.iter())
            .zip(c.iter())
            .zip(d.iter())
            .for_each(|(((left, right), output), fourth)| {
                f_table.push(left);
            });
    }
}
*/
