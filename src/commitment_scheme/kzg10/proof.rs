// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::Commitment;
use dusk_bls12_381::BlsScalar;

/// Proof that a polynomial `p` was correctly evaluated at a point `z`
/// producing the evaluated point p(z).
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct Proof {
    /// This is a commitment to the witness polynomial.
    pub(crate) commitment_to_witness: Commitment,
    /// This is the result of evaluating a polynomial at the point `z`.
    pub(crate) evaluated_point: BlsScalar,
    /// This is the commitment to the polynomial that you want to prove a
    /// statement about.
    pub(crate) commitment_to_polynomial: Commitment,
}

#[cfg(feature = "alloc")]
pub(crate) mod alloc {
    use super::*;
    use crate::util::powers_of;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use dusk_bls12_381::G1Projective;
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    /// Proof that multiple polynomials were correctly evaluated at a point `z`,
    /// each producing their respective evaluated points p_i(z).
    #[derive(Debug)]
    #[allow(dead_code)]
    pub(crate) struct AggregateProof {
        /// This is a commitment to the aggregated witness polynomial.
        pub(crate) commitment_to_witness: Commitment,
        /// These are the results of the evaluating each polynomial at the
        /// point `z`.
        pub(crate) evaluated_points: Vec<BlsScalar>,
        /// These are the commitments to the polynomials which you want to
        /// prove a statement about.
        pub(crate) commitments_to_polynomials: Vec<Commitment>,
    }

    #[allow(dead_code)]
    impl AggregateProof {
        /// Initializes an `AggregatedProof` with the commitment to the witness.
        pub(crate) fn with_witness(witness: Commitment) -> AggregateProof {
            AggregateProof {
                commitment_to_witness: witness,
                evaluated_points: Vec::new(),
                commitments_to_polynomials: Vec::new(),
            }
        }

        /// Adds an evaluated point with the commitment to the polynomial which
        /// produced it.
        pub(crate) fn add_part(&mut self, part: (BlsScalar, Commitment)) {
            self.evaluated_points.push(part.0);
            self.commitments_to_polynomials.push(part.1);
        }

        /// Flattens an `AggregateProof` into a `Proof`.
        pub(crate) fn flatten(&self, v_challenge: &BlsScalar) -> Proof {
            let powers = powers_of(
                v_challenge,
                self.commitments_to_polynomials.len() - 1,
            );

            #[cfg(not(feature = "std"))]
            let flattened_poly_commitments_iter =
                self.commitments_to_polynomials.iter().zip(powers.iter());
            #[cfg(not(feature = "std"))]
            let flattened_poly_evaluations_iter =
                self.evaluated_points.iter().zip(powers.iter());

            #[cfg(feature = "std")]
            let flattened_poly_commitments_iter = self
                .commitments_to_polynomials
                .par_iter()
                .zip(powers.par_iter());
            #[cfg(feature = "std")]
            let flattened_poly_evaluations_iter =
                self.evaluated_points.par_iter().zip(powers.par_iter());

            // Flattened polynomial commitments using challenge `v`
            let flattened_poly_commitments: G1Projective =
                flattened_poly_commitments_iter
                    .map(|(poly, v_challenge)| poly.0 * v_challenge)
                    .sum();
            // Flattened evaluation points
            let flattened_poly_evaluations: BlsScalar =
                flattened_poly_evaluations_iter
                    .map(|(eval, v_challenge)| eval * v_challenge)
                    .sum();

            Proof {
                commitment_to_witness: self.commitment_to_witness,
                evaluated_point: flattened_poly_evaluations,
                commitment_to_polynomial: Commitment::from(
                    flattened_poly_commitments,
                ),
            }
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use dusk_bls12_381::{G1Affine, G1Projective};

    #[test]
    fn aggregate_proof_flatten_is_linear_combination() {
        // Build an aggregate proof with 3 parts.
        let witness_commitment: Commitment = G1Affine::generator().into();
        let mut agg = alloc::AggregateProof::with_witness(witness_commitment);

        let c0: Commitment =
            (G1Projective::generator() * BlsScalar::from(2u64)).into();
        let c1: Commitment =
            (G1Projective::generator() * BlsScalar::from(3u64)).into();
        let c2: Commitment =
            (G1Projective::generator() * BlsScalar::from(5u64)).into();

        let e0 = BlsScalar::from(11u64);
        let e1 = BlsScalar::from(13u64);
        let e2 = BlsScalar::from(17u64);

        agg.add_part((e0, c0));
        agg.add_part((e1, c1));
        agg.add_part((e2, c2));

        let v = BlsScalar::from(7u64);

        let proof = agg.flatten(&v);

        // commitment_to_witness is left unchanged.
        assert_eq!(proof.commitment_to_witness, witness_commitment);

        let powers = crate::util::powers_of(&v, 2);
        assert_eq!(powers.len(), 3);

        let expected_eval = e0 * powers[0] + e1 * powers[1] + e2 * powers[2];
        assert_eq!(proof.evaluated_point, expected_eval);

        let expected_commitment_proj: G1Projective =
            c0.0 * &powers[0] + c1.0 * &powers[1] + c2.0 * &powers[2];
        let expected_commitment: Commitment = expected_commitment_proj.into();

        assert_eq!(proof.commitment_to_polynomial, expected_commitment);
    }
}
