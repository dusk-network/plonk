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

/// Struct for the meantime 
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PlookupTable5Arity = [[BlsScalar; 4]; 16];

/// Hash table containing fixed binary
/// possibilities for Hash
pub const HASH_TABLE_TWO: PlookupTable5Arity = PlookupTable5Arity([
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
]);
