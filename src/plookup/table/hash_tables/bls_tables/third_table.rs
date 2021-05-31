// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::plookup::PlookupTable4Arity;
/// This file contains a hard-coded version of the
/// third constraint table required in the zelbet
/// hash function.
///
use crate::prelude::BlsScalar;

pub fn table_3() -> PlookupTable4Arity {
    let mut table_3 = Vec::new();
    let two = BlsScalar::from(2);

    // Construct lines 1 to 2
    (0..2).for_each(|i| {
        table_3.push([
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::from(i),
        ])
    });
    // Construct lines 3 to 6
    (0..2).for_each(|i| {
        (1..3).for_each(|j| {
            table_3.push([
                BlsScalar::zero(),
                BlsScalar::from(i),
                BlsScalar::one(),
                BlsScalar::from(j),
            ])
        })
    });
    // Construct lines 7 to 8
    (1..3)
        .for_each(|i| table_3.push([BlsScalar::zero(), BlsScalar::one(), two, BlsScalar::from(i)]));
    // Construct remaining lines
    (1..3).for_each(|i| {
        (1..3).for_each(|j| {
            (1..3).for_each(|k| {
                (1..3).for_each(|m| {
                    table_3.push([
                        BlsScalar::from(i),
                        BlsScalar::from(j),
                        BlsScalar::from(k),
                        BlsScalar::from(m),
                    ])
                })
            })
        })
    });

    PlookupTable4Arity(table_3)
}
