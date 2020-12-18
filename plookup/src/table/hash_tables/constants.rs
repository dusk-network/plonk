// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

// For the Bls and BN254 curves, the large prime p is different.
// This leads to diffences in the subsequent difference in constants
// we have defined below.
// These are the required constants for the
// Currently making the s_i usize.

pub const V: usize = 643;
pub const N: u64 = 27;
// Note this is currently backwards, e.g. S[0] should = 673. But doesn't matter for now
pub const S: [u64; 27] = [
    651, 658, 656, 666, 663, 654, 668, 677, 681, 683, 669, 681, 680, 677, 675, 668, 675, 683, 681,
    683, 683, 655, 680, 683, 667, 678, 673,
];
pub const T_S: usize = 4;

