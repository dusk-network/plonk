// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

use dusk_bls12_381::Scalar;

/// Constants used in the permutation argument to ensure that the wire subsets are disjoint.
pub(crate) const K1: Scalar = Scalar::from_raw([7, 0, 0, 0]);
pub(crate) const K2: Scalar = Scalar::from_raw([13, 0, 0, 0]);
pub(crate) const K3: Scalar = Scalar::from_raw([17, 0, 0, 0]);
