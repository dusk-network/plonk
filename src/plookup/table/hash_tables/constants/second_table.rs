// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

/// This file contains a hard-coded version of the 
/// second constraint table required in the zelbet 
/// hash function.



/// Hash table containing fixed binary
/// possibilities for Hash
pub const HASH_TABLE_TWO: HashTableTwo = HashTableTwo([
    [
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    ],
    [
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::one(),
    ],
    [
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::zero(),
    ],
    [
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::one(),
    ],
    [
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    ],
    [
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::one(),
    ],
    [
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
    ],
    [
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
    ],
    [
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    ],
    [
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::one(),
    ],
    [
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::zero(),
    ],
    [
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::one(),
    ],
    [
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    ],
    [
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::one(),
    ],
    [
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::zero(),
    ],
    [
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
        BlsScalar::one(),
    ],
]);