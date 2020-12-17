// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

// For the Bls and BN254 curves, the large prime p is different. 
// This leads to diffences in the subsequent difference in constants 
// we have defined below. values of p (and therefore of
// the s_i, etc.)
// These are the required constants for the 
// Currently making the s_i usize, but in reality I think they should be BlsScalars

// const p: usize = 52435875175126190479447740508185965837690552500527637822603658699938581184513;
pub const V: usize = 643;
pub const N: u64 = 27;
// Note this is currently backwards, e.g. S[0] should = 673. But doesn't matter for now
pub const S: [u64; 27] = [651,658,656,666,663,654,668,
                        677,681,683,669,681,680,677,675,
                        668,675,683,681,683,683,655,680,
                        683,667,678,673];
pub const T_S: usize = 4;

/// F is a polynomial; we will represent it as a vector of coefficients.
/// We will make F the simple bijection that adds 3 to each element for now.
/// The first entry represents the coefficient of the highest power, the 
/// last entry is the constant in the polynomial.
/// But this approach also seems to require knowing beforehand the degree of F.
/// Perhaps we could find a max degree D for F and then always input F as D-sized vector
pub const F: [u64; 2] = [1, 3];