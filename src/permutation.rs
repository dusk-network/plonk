// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::{WireData, Witness};
use crate::fft::{EvaluationDomain, Polynomial};
use alloc::vec::Vec;
use constants::{K1, K2, K3};
use dusk_bls12_381::BlsScalar;
use hashbrown::HashMap;
use itertools::izip;

pub(crate) mod constants;

#[cfg(feature = "std")]
use rayon::iter::{IntoParallelIterator, ParallelIterator};

/// Permutation provides the necessary state information and functions
/// to create the permutation polynomial. In the literature, Z(X) is the
/// "accumulator", this is what this codebase calls the permutation polynomial.
#[derive(Debug)]
pub(crate) struct Permutation {
    // Maps a variable to the wires that it is associated to.
    pub(crate) variable_map: HashMap<Witness, Vec<WireData>>,
}

impl Permutation {
    /// Creates a Permutation struct with an expected capacity of zero.
    pub(crate) fn new() -> Permutation {
        Permutation::with_capacity(0)
    }

    /// Creates a Permutation struct with an expected capacity of `n`.
    pub(crate) fn with_capacity(size: usize) -> Permutation {
        Permutation {
            variable_map: HashMap::with_capacity(size),
        }
    }

    /// Creates a new [`Witness`] by incrementing the index of the
    /// `variable_map`.
    ///
    /// This is correct as whenever we add a new [`Witness`] into the system It
    /// is always allocated in the `variable_map`.
    pub(crate) fn new_variable(&mut self) -> Witness {
        // Generate the Witness
        let var = Witness::new(self.variable_map.keys().len());

        // Allocate space for the Witness on the variable_map
        // Each vector is initialised with a capacity of 16.
        // This number is a best guess estimate.
        self.variable_map.insert(var, Vec::with_capacity(16usize));

        var
    }

    /// Checks that the [`Witness`]s are valid by determining if they have been
    /// added to the system
    fn valid_variables(&self, variables: &[Witness]) -> bool {
        variables
            .iter()
            .all(|var| self.variable_map.contains_key(var))
    }

    /// Maps a set of [`Witness`]s (a,b,c,d) to a set of [`Wire`](WireData)s
    /// (left, right, out, fourth) with the corresponding gate index
    pub fn add_variables_to_map<T: Into<Witness>>(
        &mut self,
        a: T,
        b: T,
        c: T,
        d: T,
        gate_index: usize,
    ) {
        let left: WireData = WireData::Left(gate_index);
        let right: WireData = WireData::Right(gate_index);
        let output: WireData = WireData::Output(gate_index);
        let fourth: WireData = WireData::Fourth(gate_index);

        // Map each variable to the wire it is associated with
        // This essentially tells us that:
        self.add_variable_to_map(a.into(), left);
        self.add_variable_to_map(b.into(), right);
        self.add_variable_to_map(c.into(), output);
        self.add_variable_to_map(d.into(), fourth);
    }

    pub(crate) fn add_variable_to_map<T: Into<Witness> + Copy>(
        &mut self,
        var: T,
        wire_data: WireData,
    ) {
        assert!(self.valid_variables(&[var.into()]));

        // Since we always allocate space for the Vec of WireData when a
        // Witness is added to the variable_map, this should never fail
        let vec_wire_data = self.variable_map.get_mut(&var.into()).unwrap();
        vec_wire_data.push(wire_data);
    }

    // Performs shift by one permutation and computes sigma_1, sigma_2 and
    // sigma_3, sigma_4 permutations from the variable maps
    pub(super) fn compute_sigma_permutations(
        &mut self,
        n: usize,
    ) -> [Vec<WireData>; 4] {
        let sigma_1: Vec<_> = (0..n).map(WireData::Left).collect();
        let sigma_2: Vec<_> = (0..n).map(WireData::Right).collect();
        let sigma_3: Vec<_> = (0..n).map(WireData::Output).collect();
        let sigma_4: Vec<_> = (0..n).map(WireData::Fourth).collect();

        let mut sigmas = [sigma_1, sigma_2, sigma_3, sigma_4];

        for (_, wire_data) in self.variable_map.iter() {
            // Gets the data for each wire associated with this variable
            for (wire_index, current_wire) in wire_data.iter().enumerate() {
                // Fetch index of the next wire, if it is the last element
                // We loop back around to the beginning
                let next_index = match wire_index == wire_data.len() - 1 {
                    true => 0,
                    false => wire_index + 1,
                };

                // Fetch the next wire
                let next_wire = &wire_data[next_index];

                // Map current wire to next wire
                match current_wire {
                    WireData::Left(index) => sigmas[0][*index] = *next_wire,
                    WireData::Right(index) => sigmas[1][*index] = *next_wire,
                    WireData::Output(index) => sigmas[2][*index] = *next_wire,
                    WireData::Fourth(index) => sigmas[3][*index] = *next_wire,
                };
            }
        }

        sigmas
    }

    fn compute_permutation_lagrange(
        &self,
        sigma_mapping: &[WireData],
        domain: &EvaluationDomain,
    ) -> Vec<BlsScalar> {
        let roots: Vec<_> = domain.elements().collect();

        let lagrange_poly: Vec<BlsScalar> = sigma_mapping
            .iter()
            .map(|x| match x {
                WireData::Left(index) => {
                    let root = &roots[*index];
                    *root
                }
                WireData::Right(index) => {
                    let root = &roots[*index];
                    K1 * root
                }
                WireData::Output(index) => {
                    let root = &roots[*index];
                    K2 * root
                }
                WireData::Fourth(index) => {
                    let root = &roots[*index];
                    K3 * root
                }
            })
            .collect();

        lagrange_poly
    }

    /// Computes the sigma polynomials which are used to build the permutation
    /// polynomial
    pub(crate) fn compute_sigma_polynomials(
        &mut self,
        n: usize,
        domain: &EvaluationDomain,
    ) -> [Polynomial; 4] {
        // Compute sigma mappings
        let sigmas = self.compute_sigma_permutations(n);

        assert_eq!(sigmas[0].len(), n);
        assert_eq!(sigmas[1].len(), n);
        assert_eq!(sigmas[2].len(), n);
        assert_eq!(sigmas[3].len(), n);

        // define the sigma permutations using two non quadratic residues
        let left_sigma = self.compute_permutation_lagrange(&sigmas[0], domain);
        let right_sigma = self.compute_permutation_lagrange(&sigmas[1], domain);
        let out_sigma = self.compute_permutation_lagrange(&sigmas[2], domain);
        let fourth_sigma =
            self.compute_permutation_lagrange(&sigmas[3], domain);

        let left_sigma_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&left_sigma));
        let right_sigma_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&right_sigma));
        let out_sigma_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&out_sigma));
        let fourth_sigma_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&fourth_sigma));

        [
            left_sigma_poly,
            right_sigma_poly,
            out_sigma_poly,
            fourth_sigma_poly,
        ]
    }

    // Uses a rayon multizip to allow more code flexibility while remaining
    // parallelizable. This can be adapted into a general product argument
    // for any number of wires.
    pub(crate) fn compute_permutation_poly(
        &self,
        domain: &EvaluationDomain,
        wires: [&[BlsScalar]; 4],
        beta: &BlsScalar,
        gamma: &BlsScalar,
        sigma_polys: [&Polynomial; 4],
    ) -> Polynomial {
        let n = domain.size();

        // Constants defining cosets H, k1H, k2H, etc
        let ks = vec![BlsScalar::one(), K1, K2, K3];

        // Transpose wires and sigma values to get "rows" in the form [wl_i,
        // wr_i, wo_i, ... ] where each row contains the wire and sigma
        // values for a single gate
        let gatewise_wires = izip!(wires[0], wires[1], wires[2], wires[3])
            .map(|(w0, w1, w2, w3)| vec![w0, w1, w2, w3]);

        let gatewise_sigmas: Vec<Vec<BlsScalar>> =
            sigma_polys.iter().map(|sigma| domain.fft(sigma)).collect();
        let gatewise_sigmas = izip!(
            &gatewise_sigmas[0],
            &gatewise_sigmas[1],
            &gatewise_sigmas[2],
            &gatewise_sigmas[3]
        )
        .map(|(s0, s1, s2, s3)| vec![s0, s1, s2, s3]);

        // Compute all roots
        // Non-parallelizable?
        let roots: Vec<BlsScalar> = domain.elements().collect();

        let product_argument = izip!(roots, gatewise_sigmas, gatewise_wires)
            // Associate each wire value in a gate with the k defining its coset
            .map(|(gate_root, gate_sigmas, gate_wires)| {
                (gate_root, izip!(gate_sigmas, gate_wires, &ks))
            })
            // Now the ith element represents gate i and will have the form:
            //   (root_i, ((w0_i, s0_i, k0), (w1_i, s1_i, k1), ..., (wm_i, sm_i,
            // km)))   for m different wires, which is all the
            // information   needed for a single product coefficient
            // for a single gate Multiply up the numerator and
            // denominator irreducibles for each gate   and pair the
            // results
            .map(|(gate_root, wire_params)| {
                (
                    // Numerator product
                    wire_params
                        .clone()
                        .map(|(_sigma, wire, k)| {
                            wire + beta * k * gate_root + gamma
                        })
                        .product::<BlsScalar>(),
                    // Denominator product
                    wire_params
                        .map(|(sigma, wire, _k)| wire + beta * sigma + gamma)
                        .product::<BlsScalar>(),
                )
            })
            // Divide each pair to get the single scalar representing each gate
            .map(|(n, d)| n * d.invert().unwrap())
            // Collect into vector intermediary since rayon does not support
            // `scan`
            .collect::<Vec<BlsScalar>>();

        let mut z = Vec::with_capacity(n);

        // First element is one
        let mut state = BlsScalar::one();
        z.push(state);

        // Accumulate by successively multiplying the scalars
        // Non-parallelizable?
        for s in product_argument {
            state *= s;
            z.push(state);
        }

        // Remove the last(n+1'th) element
        z.remove(n);

        assert_eq!(n, z.len());

        Polynomial::from_coefficients_vec(domain.ifft(&z))
    }

    pub(crate) fn compute_lookup_permutation_poly(
        &self,
        domain: &EvaluationDomain,
        f: &[BlsScalar],
        t: &[BlsScalar],
        h_1: &[BlsScalar],
        h_2: &[BlsScalar],
        delta: &BlsScalar,
        epsilon: &BlsScalar,
    ) -> Polynomial {
        let n = domain.size();

        assert_eq!(f.len(), domain.size());
        assert_eq!(t.len(), domain.size());
        assert_eq!(h_1.len(), domain.size());
        assert_eq!(h_2.len(), domain.size());

        let t_next: Vec<BlsScalar> = [&t[1..], &[t[0]]].concat();
        let h_1_next: Vec<BlsScalar> = [&h_1[1..], &[h_1[0]]].concat();

        #[cfg(feature = "std")]
        let product_arguments: Vec<BlsScalar> =
            (f, t, t_next, h_1, h_1_next, h_2)
                .into_par_iter()
                // Derive the numerator and denominator for each gate plonkup
                // gate and pair the results
                .map(|(f, t, t_next, h_1, h_1_next, h_2)| {
                    (
                        plonkup_numerator_irreducible(
                            delta, epsilon, f, t, t_next,
                        ),
                        plonkup_denominator_irreducible(
                            delta, epsilon, h_1, &h_1_next, h_2,
                        ),
                    )
                })
                .map(|(num, den)| num * den.invert().unwrap())
                .collect();

        #[cfg(not(feature = "std"))]
        let product_arguments: Vec<BlsScalar> = f
            .iter()
            .zip(t)
            .zip(t_next)
            .zip(h_1)
            .zip(h_1_next)
            .zip(h_2)
            // Derive the numerator and denominator for each gate plonkup
            // gate and pair the results
            .map(|(((((f, t), t_next), h_1), h_1_next), h_2)| {
                (
                    plonkup_numerator_irreducible(
                        delta, epsilon, &f, &t, t_next,
                    ),
                    plonkup_denominator_irreducible(
                        delta, epsilon, &h_1, &h_1_next, &h_2,
                    ),
                )
            })
            .map(|(num, den)| num * den.invert().unwrap())
            .collect();

        let mut state = BlsScalar::one();
        let mut p = Vec::with_capacity(n);
        p.push(state);

        for s in product_arguments {
            state *= s;
            p.push(state);
        }

        // remove the last element
        p.remove(n);

        assert_eq!(n, p.len());

        Polynomial::from_coefficients_vec(domain.ifft(&p))
    }
}

fn plonkup_numerator_irreducible(
    delta: &BlsScalar,
    epsilon: &BlsScalar,
    f: &BlsScalar,
    t: &BlsScalar,
    t_next: BlsScalar,
) -> BlsScalar {
    let prod_1 = epsilon + f;
    let prod_2 = BlsScalar::one() + delta;
    let prod_3 = (epsilon * prod_2) + t + (delta * t_next);

    prod_1 * prod_2 * prod_3
}

fn plonkup_denominator_irreducible(
    delta: &BlsScalar,
    epsilon: &BlsScalar,
    h_1: &BlsScalar,
    h_1_next: &BlsScalar,
    h_2: &BlsScalar,
) -> BlsScalar {
    let epsilon_plus_one_delta = epsilon * (BlsScalar::one() + delta);
    let prod_1 = epsilon_plus_one_delta + h_1 + (h_2 * delta);
    let prod_2 = epsilon_plus_one_delta + h_2 + (h_1_next * delta);

    prod_1 * prod_2
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::constraint_system::{Constraint, TurboComposer};
    use crate::error::Error;
    use crate::fft::Polynomial;
    use crate::plonkup::MultiSet;
    use dusk_bls12_381::BlsScalar;
    use rand_core::OsRng;

    #[test]
    fn test_compute_lookup_permutation_poly() -> Result<(), Error> {
        // FIXME: use `usize` everywhere for such things
        const SIZE: u32 = 4;

        let delta = BlsScalar::from(10);
        let epsilon = BlsScalar::from(20);

        let mut t = MultiSet::from(
            &[BlsScalar::one(), BlsScalar::from(2), BlsScalar::from(3)][..],
        );
        t.pad(SIZE);

        let mut f = MultiSet::from(
            &[BlsScalar::one(), BlsScalar::from(3), BlsScalar::from(3)][..],
        );
        f.pad(SIZE);

        let mut h_1 = MultiSet::from(
            &[BlsScalar::one(), BlsScalar::one(), BlsScalar::one()][..],
        );
        h_1.pad(SIZE);

        let mut h_2 = MultiSet::from(
            &[BlsScalar::from(2), BlsScalar::from(3), BlsScalar::one()][..],
        );
        h_2.pad(SIZE);

        let domain = EvaluationDomain::new(SIZE as usize)?;
        let perm = Permutation::new();

        let poly = perm.compute_lookup_permutation_poly(
            &domain, &f.0, &t.0, &h_1.0, &h_2.0, &delta, &epsilon,
        );

        const TEST_VECTORS: [&str; 4] = [
            "0x0eaa2fe1c155cfb88bf91f7800c3b855fc67989c949da6cc87a68c9499680d1c",
            "0x077d37bc33db4e8809cc64da6e65d911d3d14ae877e61d9afe13d8229c3c9667",
            "0x504f5bba23e3439bb5c1ac5968bea1db2491ad7237d03f4cccc5258c605c3e17",
            "0x9e893da8e4eb9d23b330cb532e61476416e5b21bcc5b6fb33d7ab00f104df94c",
        ];

        assert_eq!(TEST_VECTORS.len(), poly.coeffs.len());

        for i in 0..TEST_VECTORS.len() {
            assert_eq!(format!("{:#x}", poly.coeffs[i]), TEST_VECTORS[i]);
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn compute_fast_permutation_poly(
        domain: &EvaluationDomain,
        w_l: &[BlsScalar],
        w_r: &[BlsScalar],
        w_o: &[BlsScalar],
        w_4: &[BlsScalar],
        beta: &BlsScalar,
        gamma: &BlsScalar,
        (left_sigma_poly, right_sigma_poly, out_sigma_poly, fourth_sigma_poly): (
            &Polynomial,
            &Polynomial,
            &Polynomial,
            &Polynomial,
        ),
    ) -> Vec<BlsScalar> {
        let n = domain.size();

        // Compute beta * roots
        let common_roots: Vec<BlsScalar> =
            domain.elements().map(|root| root * beta).collect();

        let left_sigma_mapping = domain.fft(left_sigma_poly);
        let right_sigma_mapping = domain.fft(right_sigma_poly);
        let out_sigma_mapping = domain.fft(out_sigma_poly);
        let fourth_sigma_mapping = domain.fft(fourth_sigma_poly);

        // Compute beta * sigma polynomials
        let beta_left_sigmas: Vec<_> = left_sigma_mapping
            .iter()
            .map(|sigma| sigma * beta)
            .collect();
        let beta_right_sigmas: Vec<_> = right_sigma_mapping
            .iter()
            .map(|sigma| sigma * beta)
            .collect();
        let beta_out_sigmas: Vec<_> =
            out_sigma_mapping.iter().map(|sigma| sigma * beta).collect();
        let beta_fourth_sigmas: Vec<_> = fourth_sigma_mapping
            .iter()
            .map(|sigma| sigma * beta)
            .collect();

        // Compute beta * roots * K1
        let beta_roots_k1: Vec<_> =
            common_roots.iter().map(|x| x * K1).collect();

        // Compute beta * roots * K2
        let beta_roots_k2: Vec<_> =
            common_roots.iter().map(|x| x * K2).collect();

        // Compute beta * roots * K3
        let beta_roots_k3: Vec<_> =
            common_roots.iter().map(|x| x * K3).collect();

        // Compute left_wire + gamma
        let w_l_gamma: Vec<_> = w_l.iter().map(|w_l| w_l + gamma).collect();

        // Compute right_wire + gamma
        let w_r_gamma: Vec<_> = w_r.iter().map(|w_r| w_r + gamma).collect();

        // Compute out_wire + gamma
        let w_o_gamma: Vec<_> = w_o.iter().map(|w_o| w_o + gamma).collect();

        // Compute fourth_wire + gamma
        let w_4_gamma: Vec<_> = w_4.iter().map(|w_4| w_4 + gamma).collect();

        // Compute 6 accumulator components
        // Parallelizable
        let accumulator_components_without_l1: Vec<_> = izip!(
            w_l_gamma,
            w_r_gamma,
            w_o_gamma,
            w_4_gamma,
            common_roots,
            beta_roots_k1,
            beta_roots_k2,
            beta_roots_k3,
            beta_left_sigmas,
            beta_right_sigmas,
            beta_out_sigmas,
            beta_fourth_sigmas,
        )
        .map(
            |(
                w_l_gamma,
                w_r_gamma,
                w_o_gamma,
                w_4_gamma,
                beta_root,
                beta_root_k1,
                beta_root_k2,
                beta_root_k3,
                beta_left_sigma,
                beta_right_sigma,
                beta_out_sigma,
                beta_fourth_sigma,
            )| {
                // w_j + beta * root^j-1 + gamma
                let ac1 = w_l_gamma + beta_root;

                // w_{n+j} + beta * K1 * root^j-1 + gamma
                let ac2 = w_r_gamma + beta_root_k1;

                // w_{2n+j} + beta * K2 * root^j-1 + gamma
                let ac3 = w_o_gamma + beta_root_k2;

                // w_{3n+j} + beta * K3 * root^j-1 + gamma
                let ac4 = w_4_gamma + beta_root_k3;

                // 1 / w_j + beta * sigma(j) + gamma
                let ac5 = (w_l_gamma + beta_left_sigma).invert().unwrap();

                // 1 / w_{n+j} + beta * sigma(n+j) + gamma
                let ac6 = (w_r_gamma + beta_right_sigma).invert().unwrap();

                // 1 / w_{2n+j} + beta * sigma(2n+j) + gamma
                let ac7 = (w_o_gamma + beta_out_sigma).invert().unwrap();

                // 1 / w_{3n+j} + beta * sigma(3n+j) + gamma
                let ac8 = (w_4_gamma + beta_fourth_sigma).invert().unwrap();

                [ac1, ac2, ac3, ac4, ac5, ac6, ac7, ac8]
            },
        )
        .collect();

        // Prepend ones to the beginning of each accumulator to signify L_1(x)
        let accumulator_components = core::iter::once([BlsScalar::one(); 8])
            .chain(accumulator_components_without_l1);

        // Multiply each component of the accumulators
        // A simplified example is the following:
        // A1 = [1,2,3,4]
        // result = [1, 1*2, 1*2*3, 1*2*3*4]
        // Non Parallelizable
        let mut prev = [BlsScalar::one(); 8];

        let product_accumulated_components: Vec<_> = accumulator_components
            .map(|current_component| {
                current_component
                    .iter()
                    .zip(prev.iter_mut())
                    .for_each(|(curr, prev)| *prev *= curr);
                prev
            })
            .collect();

        // Right now we basically have 6 accumulators of the form:
        // A1 = [a1, a1 * a2, a1*a2*a3,...]
        // A2 = [b1, b1 * b2, b1*b2*b3,...]
        // A3 = [c1, c1 * c2, c1*c2*c3,...]
        // ... and so on
        // We want:
        // [a1*b1*c1, a1 * a2 *b1 * b2 * c1 * c2,...]
        // Parallelizable
        let mut z: Vec<_> = product_accumulated_components
            .iter()
            .map(move |current_component| current_component.iter().product())
            .collect();
        // Remove the last(n+1'th) element
        z.remove(n);

        assert_eq!(n, z.len());

        z
    }

    fn compute_slow_permutation_poly<I>(
        domain: &EvaluationDomain,
        w_l: I,
        w_r: I,
        w_o: I,
        w_4: I,
        beta: &BlsScalar,
        gamma: &BlsScalar,
        (left_sigma_poly, right_sigma_poly, out_sigma_poly, fourth_sigma_poly): (
            &Polynomial,
            &Polynomial,
            &Polynomial,
            &Polynomial,
        ),
    ) -> (Vec<BlsScalar>, Vec<BlsScalar>, Vec<BlsScalar>)
    where
        I: Iterator<Item = BlsScalar>,
    {
        let n = domain.size();

        let left_sigma_mapping = domain.fft(left_sigma_poly);
        let right_sigma_mapping = domain.fft(right_sigma_poly);
        let out_sigma_mapping = domain.fft(out_sigma_poly);
        let fourth_sigma_mapping = domain.fft(fourth_sigma_poly);

        // Compute beta * sigma polynomials
        let beta_left_sigma_iter =
            left_sigma_mapping.iter().map(|sigma| *sigma * beta);
        let beta_right_sigma_iter =
            right_sigma_mapping.iter().map(|sigma| *sigma * beta);
        let beta_out_sigma_iter =
            out_sigma_mapping.iter().map(|sigma| *sigma * beta);
        let beta_fourth_sigma_iter =
            fourth_sigma_mapping.iter().map(|sigma| *sigma * beta);

        // Compute beta * roots
        let beta_roots_iter = domain.elements().map(|root| root * beta);

        // Compute beta * roots * K1
        let beta_roots_k1_iter = domain.elements().map(|root| K1 * beta * root);

        // Compute beta * roots * K2
        let beta_roots_k2_iter = domain.elements().map(|root| K2 * beta * root);

        // Compute beta * roots * K3
        let beta_roots_k3_iter = domain.elements().map(|root| K3 * beta * root);

        // Compute left_wire + gamma
        let w_l_gamma: Vec<_> = w_l.map(|w| w + gamma).collect();

        // Compute right_wire + gamma
        let w_r_gamma: Vec<_> = w_r.map(|w| w + gamma).collect();

        // Compute out_wire + gamma
        let w_o_gamma: Vec<_> = w_o.map(|w| w + gamma).collect();

        // Compute fourth_wire + gamma
        let w_4_gamma: Vec<_> = w_4.map(|w| w + gamma).collect();

        let mut numerator_partial_components: Vec<BlsScalar> =
            Vec::with_capacity(n);
        let mut denominator_partial_components: Vec<BlsScalar> =
            Vec::with_capacity(n);

        let mut numerator_coefficients: Vec<BlsScalar> = Vec::with_capacity(n);
        let mut denominator_coefficients: Vec<BlsScalar> =
            Vec::with_capacity(n);

        // First element in both of them is one
        numerator_coefficients.push(BlsScalar::one());
        denominator_coefficients.push(BlsScalar::one());

        // Compute numerator coefficients
        for (
            w_l_gamma,
            w_r_gamma,
            w_o_gamma,
            w_4_gamma,
            beta_root,
            beta_root_k1,
            beta_root_k2,
            beta_root_k3,
        ) in izip!(
            w_l_gamma.iter(),
            w_r_gamma.iter(),
            w_o_gamma.iter(),
            w_4_gamma.iter(),
            beta_roots_iter,
            beta_roots_k1_iter,
            beta_roots_k2_iter,
            beta_roots_k3_iter,
        ) {
            // (w_l + beta * root + gamma)
            let prod_a = beta_root + w_l_gamma;

            // (w_r + beta * root * k_1 + gamma)
            let prod_b = beta_root_k1 + w_r_gamma;

            // (w_o + beta * root * k_2 + gamma)
            let prod_c = beta_root_k2 + w_o_gamma;

            // (w_4 + beta * root * k_3 + gamma)
            let prod_d = beta_root_k3 + w_4_gamma;

            let mut prod = prod_a * prod_b * prod_c * prod_d;

            numerator_partial_components.push(prod);

            prod *= numerator_coefficients.last().unwrap();

            numerator_coefficients.push(prod);
        }

        // Compute denominator coefficients
        for (
            w_l_gamma,
            w_r_gamma,
            w_o_gamma,
            w_4_gamma,
            beta_left_sigma,
            beta_right_sigma,
            beta_out_sigma,
            beta_fourth_sigma,
        ) in izip!(
            w_l_gamma,
            w_r_gamma,
            w_o_gamma,
            w_4_gamma,
            beta_left_sigma_iter,
            beta_right_sigma_iter,
            beta_out_sigma_iter,
            beta_fourth_sigma_iter,
        ) {
            // (w_l + beta * left_sigma + gamma)
            let prod_a = beta_left_sigma + w_l_gamma;

            // (w_r + beta * right_sigma + gamma)
            let prod_b = beta_right_sigma + w_r_gamma;

            // (w_o + beta * out_sigma + gamma)
            let prod_c = beta_out_sigma + w_o_gamma;

            // (w_4 + beta * fourth_sigma + gamma)
            let prod_d = beta_fourth_sigma + w_4_gamma;

            let mut prod = prod_a * prod_b * prod_c * prod_d;

            denominator_partial_components.push(prod);

            let last_element = denominator_coefficients.last().unwrap();

            prod *= last_element;

            denominator_coefficients.push(prod);
        }

        assert_eq!(denominator_coefficients.len(), n + 1);
        assert_eq!(numerator_coefficients.len(), n + 1);

        // Check that n+1'th elements are equal (taken from proof)
        let a = numerator_coefficients.pop().unwrap();
        assert_ne!(a, BlsScalar::zero());
        let b = denominator_coefficients.pop().unwrap();
        assert_ne!(b, BlsScalar::zero());
        assert_eq!(a * b.invert().unwrap(), BlsScalar::one());

        // Combine numerator and denominator

        let mut z_coefficients: Vec<BlsScalar> = Vec::with_capacity(n);
        for (numerator, denominator) in numerator_coefficients
            .iter()
            .zip(denominator_coefficients.iter())
        {
            z_coefficients.push(*numerator * denominator.invert().unwrap());
        }
        assert_eq!(z_coefficients.len(), n);

        (
            z_coefficients,
            numerator_partial_components,
            denominator_partial_components,
        )
    }

    #[test]
    fn test_multizip_permutation_poly() {
        let mut cs = TurboComposer::with_size(4);

        let x1 = cs.append_witness(BlsScalar::from_raw([4, 0, 0, 0]));
        let x2 = cs.append_witness(BlsScalar::from_raw([12, 0, 0, 0]));
        let x3 = cs.append_witness(BlsScalar::from_raw([8, 0, 0, 0]));
        let x4 = cs.append_witness(BlsScalar::from_raw([3, 0, 0, 0]));

        let one = BlsScalar::one();
        let two = BlsScalar::from_raw([2, 0, 0, 0]);

        // x1 * x4 = x2
        let constraint =
            Constraint::new().mult(1).output(-one).a(x1).b(x4).o(x2);
        cs.append_gate(constraint);

        // x1 + x3 = x2
        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .output(-one)
            .a(x1)
            .b(x3)
            .o(x2);
        cs.append_gate(constraint);

        // x1 + x2 = 2*x3
        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .output(-two)
            .a(x1)
            .b(x2)
            .o(x3);
        cs.append_gate(constraint);

        // x3 * x4 = 2*x2
        let constraint =
            Constraint::new().mult(1).output(-two).a(x3).b(x4).o(x2);
        cs.append_gate(constraint);

        let domain = EvaluationDomain::new(cs.gates()).unwrap();
        let pad = vec![BlsScalar::zero(); domain.size() - cs.w_l.len()];
        let mut w_l_scalar: Vec<BlsScalar> =
            cs.w_l.iter().map(|v| cs.witnesses[v]).collect();
        let mut w_r_scalar: Vec<BlsScalar> =
            cs.w_r.iter().map(|v| cs.witnesses[v]).collect();
        let mut w_o_scalar: Vec<BlsScalar> =
            cs.w_o.iter().map(|v| cs.witnesses[v]).collect();
        let mut w_4_scalar: Vec<BlsScalar> =
            cs.w_4.iter().map(|v| cs.witnesses[v]).collect();

        w_l_scalar.extend(&pad);
        w_r_scalar.extend(&pad);
        w_o_scalar.extend(&pad);
        w_4_scalar.extend(&pad);

        let sigmas: Vec<Vec<BlsScalar>> = cs
            .perm
            .compute_sigma_permutations(7)
            .iter()
            .map(|wd| cs.perm.compute_permutation_lagrange(wd, &domain))
            .collect();

        let beta = BlsScalar::random(&mut OsRng);
        let gamma = BlsScalar::random(&mut OsRng);

        let sigma_polys: Vec<Polynomial> = sigmas
            .iter()
            .map(|v| Polynomial::from_coefficients_vec(domain.ifft(v)))
            .collect();

        let mz = cs.perm.compute_permutation_poly(
            &domain,
            [&w_l_scalar, &w_r_scalar, &w_o_scalar, &w_4_scalar],
            &beta,
            &gamma,
            [
                &sigma_polys[0],
                &sigma_polys[1],
                &sigma_polys[2],
                &sigma_polys[3],
            ],
        );

        let old_z = Polynomial::from_coefficients_vec(domain.ifft(
            &compute_fast_permutation_poly(
                &domain,
                &w_l_scalar,
                &w_r_scalar,
                &w_o_scalar,
                &w_4_scalar,
                &beta,
                &gamma,
                (
                    &sigma_polys[0],
                    &sigma_polys[1],
                    &sigma_polys[2],
                    &sigma_polys[3],
                ),
            ),
        ));

        assert_eq!(mz, old_z);
    }

    #[test]
    fn test_permutation_format() {
        let mut perm: Permutation = Permutation::new();

        let num_variables = 10u8;
        for i in 0..num_variables {
            let var = perm.new_variable();
            assert_eq!(var.index(), i as usize);
            assert_eq!(perm.variable_map.len(), (i as usize) + 1);
        }

        let var_one = perm.new_variable();
        let var_two = perm.new_variable();
        let var_three = perm.new_variable();

        let gate_size = 100;
        for i in 0..gate_size {
            perm.add_variables_to_map(var_one, var_one, var_two, var_three, i);
        }

        // Check all gate_indices are valid
        for (_, wire_data) in perm.variable_map.iter() {
            for wire in wire_data.iter() {
                match wire {
                    WireData::Left(index)
                    | WireData::Right(index)
                    | WireData::Output(index)
                    | WireData::Fourth(index) => assert!(*index < gate_size),
                };
            }
        }
    }

    #[test]
    fn test_permutation_compute_sigmas_only_left_wires() {
        let mut perm = Permutation::new();

        let var_zero = perm.new_variable();
        let var_two = perm.new_variable();
        let var_three = perm.new_variable();
        let var_four = perm.new_variable();
        let var_five = perm.new_variable();
        let var_six = perm.new_variable();
        let var_seven = perm.new_variable();
        let var_eight = perm.new_variable();
        let var_nine = perm.new_variable();

        let num_wire_mappings = 4;

        // Add four wire mappings
        perm.add_variables_to_map(var_zero, var_zero, var_five, var_nine, 0);
        perm.add_variables_to_map(var_zero, var_two, var_six, var_nine, 1);
        perm.add_variables_to_map(var_zero, var_three, var_seven, var_nine, 2);
        perm.add_variables_to_map(var_zero, var_four, var_eight, var_nine, 3);

        /*
        var_zero = {L0, R0, L1, L2, L3}
        var_two = {R1}
        var_three = {R2}
        var_four = {R3}
        var_five = {O0}
        var_six = {O1}
        var_seven = {O2}
        var_eight = {O3}
        var_nine = {F0, F1, F2, F3}
        Left_sigma = {R0, L2, L3, L0}
        Right_sigma = {L1, R1, R2, R3}
        Out_sigma = {O0, O1, O2, O3}
        Fourth_sigma = {F1, F2, F3, F0}
        */
        let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
        let left_sigma = &sigmas[0];
        let right_sigma = &sigmas[1];
        let out_sigma = &sigmas[2];
        let fourth_sigma = &sigmas[3];

        // Check the left sigma polynomial
        assert_eq!(left_sigma[0], WireData::Right(0));
        assert_eq!(left_sigma[1], WireData::Left(2));
        assert_eq!(left_sigma[2], WireData::Left(3));
        assert_eq!(left_sigma[3], WireData::Left(0));

        // Check the right sigma polynomial
        assert_eq!(right_sigma[0], WireData::Left(1));
        assert_eq!(right_sigma[1], WireData::Right(1));
        assert_eq!(right_sigma[2], WireData::Right(2));
        assert_eq!(right_sigma[3], WireData::Right(3));

        // Check the output sigma polynomial
        assert_eq!(out_sigma[0], WireData::Output(0));
        assert_eq!(out_sigma[1], WireData::Output(1));
        assert_eq!(out_sigma[2], WireData::Output(2));
        assert_eq!(out_sigma[3], WireData::Output(3));

        // Check the output sigma polynomial
        assert_eq!(fourth_sigma[0], WireData::Fourth(1));
        assert_eq!(fourth_sigma[1], WireData::Fourth(2));
        assert_eq!(fourth_sigma[2], WireData::Fourth(3));
        assert_eq!(fourth_sigma[3], WireData::Fourth(0));

        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let w = domain.group_gen;
        let w_squared = w.pow(&[2, 0, 0, 0]);
        let w_cubed = w.pow(&[3, 0, 0, 0]);

        // Check the left sigmas have been encoded properly
        // Left_sigma = {R0, L2, L3, L0}
        // Should turn into {1 * K1, w^2, w^3, 1}
        let encoded_left_sigma =
            perm.compute_permutation_lagrange(left_sigma, &domain);
        assert_eq!(encoded_left_sigma[0], BlsScalar::one() * K1);
        assert_eq!(encoded_left_sigma[1], w_squared);
        assert_eq!(encoded_left_sigma[2], w_cubed);
        assert_eq!(encoded_left_sigma[3], BlsScalar::one());

        // Check the right sigmas have been encoded properly
        // Right_sigma = {L1, R1, R2, R3}
        // Should turn into {w, w * K1, w^2 * K1, w^3 * K1}
        let encoded_right_sigma =
            perm.compute_permutation_lagrange(right_sigma, &domain);
        assert_eq!(encoded_right_sigma[0], w);
        assert_eq!(encoded_right_sigma[1], w * K1);
        assert_eq!(encoded_right_sigma[2], w_squared * K1);
        assert_eq!(encoded_right_sigma[3], w_cubed * K1);

        // Check the output sigmas have been encoded properly
        // Out_sigma = {O0, O1, O2, O3}
        // Should turn into {1 * K2, w * K2, w^2 * K2, w^3 * K2}
        let encoded_output_sigma =
            perm.compute_permutation_lagrange(out_sigma, &domain);
        assert_eq!(encoded_output_sigma[0], BlsScalar::one() * K2);
        assert_eq!(encoded_output_sigma[1], w * K2);
        assert_eq!(encoded_output_sigma[2], w_squared * K2);
        assert_eq!(encoded_output_sigma[3], w_cubed * K2);

        // Check the fourth sigmas have been encoded properly
        // Out_sigma = {F1, F2, F3, F0}
        // Should turn into {w * K3, w^2 * K3, w^3 * K3, 1 * K3}
        let encoded_fourth_sigma =
            perm.compute_permutation_lagrange(fourth_sigma, &domain);
        assert_eq!(encoded_fourth_sigma[0], w * K3);
        assert_eq!(encoded_fourth_sigma[1], w_squared * K3);
        assert_eq!(encoded_fourth_sigma[2], w_cubed * K3);
        assert_eq!(encoded_fourth_sigma[3], K3);

        let w_l = vec![
            BlsScalar::from(2),
            BlsScalar::from(2),
            BlsScalar::from(2),
            BlsScalar::from(2),
        ];
        let w_r = vec![
            BlsScalar::from(2),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];
        let w_o = vec![
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];
        let w_4 = vec![
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];

        test_correct_permutation_poly(
            num_wire_mappings,
            perm,
            &domain,
            w_l,
            w_r,
            w_o,
            w_4,
        );
    }

    #[test]
    fn test_permutation_compute_sigmas() {
        let mut perm: Permutation = Permutation::new();

        let var_one = perm.new_variable();
        let var_two = perm.new_variable();
        let var_three = perm.new_variable();
        let var_four = perm.new_variable();

        let num_wire_mappings = 4;

        // Add four wire mappings
        perm.add_variables_to_map(var_one, var_one, var_two, var_four, 0);
        perm.add_variables_to_map(var_two, var_one, var_two, var_four, 1);
        perm.add_variables_to_map(var_three, var_three, var_one, var_four, 2);
        perm.add_variables_to_map(var_two, var_one, var_three, var_four, 3);

        /*
        Below is a sketch of the map created by adding the specific variables into the map
        var_one : {L0,R0, R1, O2, R3 }
        var_two : {O0, L1, O1, L3}
        var_three : {L2, R2, O3}
        var_four : {F0, F1, F2, F3}
        Left_Sigma : {0,1,2,3} -> {R0,O1,R2,O0}
        Right_Sigma : {0,1,2,3} -> {R1, O2, O3, L0}
        Out_Sigma : {0,1,2,3} -> {L1, L3, R3, L2}
        Fourth_Sigma : {0,1,2,3} -> {F1, F2, F3, F0}
        */
        let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
        let left_sigma = &sigmas[0];
        let right_sigma = &sigmas[1];
        let out_sigma = &sigmas[2];
        let fourth_sigma = &sigmas[3];

        // Check the left sigma polynomial
        assert_eq!(left_sigma[0], WireData::Right(0));
        assert_eq!(left_sigma[1], WireData::Output(1));
        assert_eq!(left_sigma[2], WireData::Right(2));
        assert_eq!(left_sigma[3], WireData::Output(0));

        // Check the right sigma polynomial
        assert_eq!(right_sigma[0], WireData::Right(1));
        assert_eq!(right_sigma[1], WireData::Output(2));
        assert_eq!(right_sigma[2], WireData::Output(3));
        assert_eq!(right_sigma[3], WireData::Left(0));

        // Check the output sigma polynomial
        assert_eq!(out_sigma[0], WireData::Left(1));
        assert_eq!(out_sigma[1], WireData::Left(3));
        assert_eq!(out_sigma[2], WireData::Right(3));
        assert_eq!(out_sigma[3], WireData::Left(2));

        // Check the fourth sigma polynomial
        assert_eq!(fourth_sigma[0], WireData::Fourth(1));
        assert_eq!(fourth_sigma[1], WireData::Fourth(2));
        assert_eq!(fourth_sigma[2], WireData::Fourth(3));
        assert_eq!(fourth_sigma[3], WireData::Fourth(0));

        /*
        Check that the unique encodings of the sigma polynomials have been computed properly
        Left_Sigma : {R0,O1,R2,O0}
            When encoded using w, K1,K2,K3 we have {1 * K1, w * K2, w^2 * K1, 1 * K2}
        Right_Sigma : {R1, O2, O3, L0}
            When encoded using w, K1,K2,K3 we have {w * K1, w^2 * K2, w^3 * K2, 1}
        Out_Sigma : {L1, L3, R3, L2}
            When encoded using w, K1, K2,K3 we have {w, w^3 , w^3 * K1, w^2}
        Fourth_Sigma : {0,1,2,3} -> {F1, F2, F3, F0}
            When encoded using w, K1, K2,K3 we have {w * K3, w^2 * K3, w^3 * K3, 1 * K3}
        */
        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let w = domain.group_gen;
        let w_squared = w.pow(&[2, 0, 0, 0]);
        let w_cubed = w.pow(&[3, 0, 0, 0]);
        // check the left sigmas have been encoded properly
        let encoded_left_sigma =
            perm.compute_permutation_lagrange(left_sigma, &domain);
        assert_eq!(encoded_left_sigma[0], K1);
        assert_eq!(encoded_left_sigma[1], w * K2);
        assert_eq!(encoded_left_sigma[2], w_squared * K1);
        assert_eq!(encoded_left_sigma[3], BlsScalar::one() * K2);

        // check the right sigmas have been encoded properly
        let encoded_right_sigma =
            perm.compute_permutation_lagrange(right_sigma, &domain);
        assert_eq!(encoded_right_sigma[0], w * K1);
        assert_eq!(encoded_right_sigma[1], w_squared * K2);
        assert_eq!(encoded_right_sigma[2], w_cubed * K2);
        assert_eq!(encoded_right_sigma[3], BlsScalar::one());

        // check the output sigmas have been encoded properly
        let encoded_output_sigma =
            perm.compute_permutation_lagrange(out_sigma, &domain);
        assert_eq!(encoded_output_sigma[0], w);
        assert_eq!(encoded_output_sigma[1], w_cubed);
        assert_eq!(encoded_output_sigma[2], w_cubed * K1);
        assert_eq!(encoded_output_sigma[3], w_squared);

        // check the fourth sigmas have been encoded properly
        let encoded_fourth_sigma =
            perm.compute_permutation_lagrange(fourth_sigma, &domain);
        assert_eq!(encoded_fourth_sigma[0], w * K3);
        assert_eq!(encoded_fourth_sigma[1], w_squared * K3);
        assert_eq!(encoded_fourth_sigma[2], w_cubed * K3);
        assert_eq!(encoded_fourth_sigma[3], K3);
    }

    #[test]
    fn test_basic_slow_permutation_poly() {
        let num_wire_mappings = 2;
        let mut perm = Permutation::new();
        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();

        let var_one = perm.new_variable();
        let var_two = perm.new_variable();
        let var_three = perm.new_variable();
        let var_four = perm.new_variable();

        perm.add_variables_to_map(var_one, var_two, var_three, var_four, 0);
        perm.add_variables_to_map(var_three, var_two, var_one, var_four, 1);

        let w_l: Vec<_> = vec![BlsScalar::one(), BlsScalar::from(3)];
        let w_r: Vec<_> = vec![BlsScalar::from(2), BlsScalar::from(2)];
        let w_o: Vec<_> = vec![BlsScalar::from(3), BlsScalar::one()];
        let w_4: Vec<_> = vec![BlsScalar::one(), BlsScalar::one()];

        test_correct_permutation_poly(
            num_wire_mappings,
            perm,
            &domain,
            w_l,
            w_r,
            w_o,
            w_4,
        );
    }

    // shifts the polynomials by one root of unity
    fn shift_poly_by_one(z_coefficients: Vec<BlsScalar>) -> Vec<BlsScalar> {
        let mut shifted_z_coefficients = z_coefficients;
        shifted_z_coefficients.push(shifted_z_coefficients[0]);
        shifted_z_coefficients.remove(0);
        shifted_z_coefficients
    }

    fn test_correct_permutation_poly(
        n: usize,
        mut perm: Permutation,
        domain: &EvaluationDomain,
        w_l: Vec<BlsScalar>,
        w_r: Vec<BlsScalar>,
        w_o: Vec<BlsScalar>,
        w_4: Vec<BlsScalar>,
    ) {
        // 0. Generate beta and gamma challenges
        //
        let beta = BlsScalar::random(&mut OsRng);
        let gamma = BlsScalar::random(&mut OsRng);
        assert_ne!(gamma, beta);

        //1. Compute the permutation polynomial using both methods
        let [left_sigma_poly, right_sigma_poly, out_sigma_poly, fourth_sigma_poly] =
            perm.compute_sigma_polynomials(n, domain);
        let (z_vec, numerator_components, denominator_components) =
            compute_slow_permutation_poly(
                domain,
                w_l.clone().into_iter(),
                w_r.clone().into_iter(),
                w_o.clone().into_iter(),
                w_4.clone().into_iter(),
                &beta,
                &gamma,
                (
                    &left_sigma_poly,
                    &right_sigma_poly,
                    &out_sigma_poly,
                    &fourth_sigma_poly,
                ),
            );

        let fast_z_vec = compute_fast_permutation_poly(
            domain,
            &w_l,
            &w_r,
            &w_o,
            &w_4,
            &beta,
            &gamma,
            (
                &left_sigma_poly,
                &right_sigma_poly,
                &out_sigma_poly,
                &fourth_sigma_poly,
            ),
        );
        assert_eq!(fast_z_vec, z_vec);

        // 2. First we perform basic tests on the permutation vector
        //
        // Check that the vector has length `n` and that the first element is
        // `1`
        assert_eq!(z_vec.len(), n);
        assert_eq!(&z_vec[0], &BlsScalar::one());
        //
        // Check that the \prod{f_i} / \prod{g_i} = 1
        // Where f_i and g_i are the numerator and denominator components in the
        // permutation polynomial
        let (mut a_0, mut b_0) = (BlsScalar::one(), BlsScalar::one());
        for n in numerator_components.iter() {
            a_0 *= n;
        }
        for n in denominator_components.iter() {
            b_0 *= n;
        }
        assert_eq!(a_0 * b_0.invert().unwrap(), BlsScalar::one());

        //3. Now we perform the two checks that need to be done on the
        // permutation polynomial (z)
        let z_poly = Polynomial::from_coefficients_vec(domain.ifft(&z_vec));
        //
        // Check that z(w^{n+1}) == z(1) == 1
        // This is the first check in the protocol
        assert_eq!(z_poly.evaluate(&BlsScalar::one()), BlsScalar::one());
        let n_plus_one = domain.elements().last().unwrap() * domain.group_gen;
        assert_eq!(z_poly.evaluate(&n_plus_one), BlsScalar::one());
        //
        // Check that when z is unblinded, it has the correct degree
        assert_eq!(z_poly.degree(), n - 1);
        //
        // Check relationship between z(X) and z(Xw)
        // This is the second check in the protocol
        let roots: Vec<_> = domain.elements().collect();

        for i in 1..roots.len() {
            let current_root = roots[i];
            let next_root = current_root * domain.group_gen;

            let current_identity_perm_product = &numerator_components[i];
            assert_ne!(current_identity_perm_product, &BlsScalar::zero());

            let current_copy_perm_product = &denominator_components[i];
            assert_ne!(current_copy_perm_product, &BlsScalar::zero());

            assert_ne!(
                current_copy_perm_product,
                current_identity_perm_product
            );

            let z_eval = z_poly.evaluate(&current_root);
            assert_ne!(z_eval, BlsScalar::zero());

            let z_eval_shifted = z_poly.evaluate(&next_root);
            assert_ne!(z_eval_shifted, BlsScalar::zero());

            // Z(Xw) * copy_perm
            let lhs = z_eval_shifted * current_copy_perm_product;
            // Z(X) * iden_perm
            let rhs = z_eval * current_identity_perm_product;
            assert_eq!(
                lhs, rhs,
                "check failed at index: {}\'n lhs is : {:?} \n rhs is :{:?}",
                i, lhs, rhs
            );
        }

        // Test that the shifted polynomial is correct
        let shifted_z = shift_poly_by_one(fast_z_vec);
        let shifted_z_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&shifted_z));
        for element in domain.elements() {
            let z_eval = z_poly.evaluate(&(element * domain.group_gen));
            let shifted_z_eval = shifted_z_poly.evaluate(&element);

            assert_eq!(z_eval, shifted_z_eval)
        }
    }
}
