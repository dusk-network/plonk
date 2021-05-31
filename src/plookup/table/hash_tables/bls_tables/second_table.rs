// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::plookup::PlookupTable4Arity;
/// This file contains a hard-coded version of the
/// second constraint table required in the zelbet
/// hash function.
use crate::prelude::BlsScalar;

pub fn table_2() -> PlookupTable4Arity {
    let mut table_2 = Vec::new();
    (0..2).for_each(|i| {
        (0..2).for_each(|j| {
            (0..2).for_each(|k| {
                (0..2).for_each(|m| {
                    table_2.push([
                        BlsScalar::from(i),
                        BlsScalar::from(j),
                        BlsScalar::from(k),
                        BlsScalar::from(m),
                    ])
                })
            })
        })
    });

    PlookupTable4Arity(table_2)
}
