// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

/// Constants used in the permutation argument to ensure that the wire subsets
/// are disjoint.
pub(crate) const K1: BlsScalar = BlsScalar::from_raw([7, 0, 0, 0]);
pub(crate) const K2: BlsScalar = BlsScalar::from_raw([13, 0, 0, 0]);
pub(crate) const K3: BlsScalar = BlsScalar::from_raw([17, 0, 0, 0]);
