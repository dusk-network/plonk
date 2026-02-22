// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

/// Constants used in the permutation argument to ensure that the wire subsets
/// are disjoint.
///
/// `K3 = 17` is a quadratic residue in Fr, but the required invariant here is
/// pairwise disjoint cosets `{H, K1*H, K2*H, K3*H}` for the subgroup `H`.
pub(crate) const K1: BlsScalar = BlsScalar::from_raw([7, 0, 0, 0]);
pub(crate) const K2: BlsScalar = BlsScalar::from_raw([13, 0, 0, 0]);
pub(crate) const K3: BlsScalar = BlsScalar::from_raw([17, 0, 0, 0]);

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn in_pow2_subgroup(x: BlsScalar, log_n: u32) -> bool {
        let n = 1u64 << log_n;
        x.pow(&[n, 0, 0, 0]) == BlsScalar::one()
    }

    #[test]
    fn k_cosets_remain_pairwise_disjoint_for_supported_pow2_domains() {
        let ks = [K1, K2, K3];
        let ratios = [
            K1 * K2.invert().unwrap(),
            K1 * K3.invert().unwrap(),
            K2 * K3.invert().unwrap(),
        ];

        // BLS12-381 Fr supports roots of unity up to size 2^32.
        for log_n in 1..=32 {
            for k in ks {
                assert!(
                    !in_pow2_subgroup(k, log_n),
                    "K constant unexpectedly in H_2^{log_n}"
                );
            }

            for ratio in ratios {
                assert!(
                    !in_pow2_subgroup(ratio, log_n),
                    "K ratio unexpectedly in H_2^{log_n}"
                );
            }
        }
    }
}
