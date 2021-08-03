// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[inline(always)]
pub const fn full_shl(u: &[u64; 4], shift: u32) -> ([u64; 4], u64) {
    // assert!(shift <= 64u32);

    let mut res = [0u64; 4];
    let shift_high: u32 = 64u32 - shift;

    res[1] = u[0] >> shift_high;
    res[2] = u[1] >> shift_high;
    res[3] = u[2] >> shift_high;

    res[0] = u[0] << shift;
    res[1] |= u[1] << shift;
    res[2] |= u[2] << shift;
    res[3] |= u[3] << shift;

    (res, u[3] >> shift_high)
}

pub const fn compute_normalized_divisor_and_reciproical(
    input: u16,
) -> (u64, u64) {
    let s = (input as u64).leading_zeros();
    let normalized_divisor = (input as u64) << s;
    let reciproical = u128::MAX / (normalized_divisor as u128) - (1u128 << 64);

    (normalized_divisor, reciproical as u64)
}

#[inline(always)]
const fn split(a: u128) -> (u64, u64) {
    ((a >> 64) as u64, a as u64)
}

#[inline(always)]
const fn div_mod_word_by_short_normalized(
    u1: u64,
    u0: u64,
    divisor: u64,
    recip: u64,
) -> (u64, u64) {
    let qq = (u1 as u128) * (recip as u128);
    let qq = qq + ((u1 as u128) << 64) + (u0 as u128);
    let (q1, q0) = split(qq);
    let mut q1 = q1.wrapping_add(1u64);
    let mut r = u0.wrapping_sub(q1.wrapping_mul(divisor));
    if r > q0 {
        q1 = q1.wrapping_sub(1u64);
        r = r.wrapping_add(divisor);
    }
    if r >= divisor {
        q1 = q1 + 1;
        r = r - divisor;
    }

    (q1, r)
}

#[inline(always)]
pub const fn divide_long_using_recip(
    a: &[u64; 4],
    divisor: u64,
    recip: u64,
    norm_shift: u32,
) -> ([u64; 4], u16) {
    let mut result = [0u64; 4];
    let (shifted, o) = full_shl(a, norm_shift);
    let (q, r) =
        div_mod_word_by_short_normalized(o, shifted[3], divisor, recip);
    result[3] = q;

    let (q, r) =
        div_mod_word_by_short_normalized(r, shifted[2], divisor, recip);
    result[2] = q;

    let (q, r) =
        div_mod_word_by_short_normalized(r, shifted[1], divisor, recip);
    result[1] = q;

    let (q, r) =
        div_mod_word_by_short_normalized(r, shifted[0], divisor, recip);
    result[0] = q;

    (result, (r >> norm_shift) as u16)
}
//-----------------------------------------------------------------------------

// example:
fn main() {
    let nom = [1u64; 4];
    let div: u16 = 1023;

    // preocomputation
    let (divisor, recip) = compute_normalized_divisor_and_reciproical(div);
    let s = (div as u64).leading_zeros();

    // division: nom / div
    let (result, remainder) = divide_long_using_recip(&nom, divisor, recip, s);
}

#[test]

fn test_divide_w_recip() {
    // let nom = [1u64; 4];
    let nom = [47, 0, 0, 0];
    // let div: u16 = 1023;
    let div: u16 = 7;

    // preocomputation
    let (divisor, recip) = compute_normalized_divisor_and_reciproical(div);
    let s = (div as u64).leading_zeros();

    // division: nom / div
    let (result, remainder) = divide_long_using_recip(&nom, divisor, recip, s);
    std::println!("result: {:?}", result);
    std::println!("remainder: {:?}", remainder);
}
