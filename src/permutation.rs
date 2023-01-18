// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::constraint_system::{WireData, Witness};
use crate::fft::{EvaluationDomain, Polynomial};
use alloc::vec::Vec;
use constants::{K1, K2, K3};
use hashbrown::HashMap;
use itertools::izip;
use sp_std::vec;
use zero_bls12_381::Fr as BlsScalar;
use zero_crypto::behave::*;
use zero_kzg::{Fft, Polynomial as ZeroPoly};

pub(crate) mod constants;

/// Permutation provides the necessary state information and functions
/// to create the permutation polynomial. In the literature, Z(X) is the
/// "accumulator", this is what this codebase calls the permutation polynomial.
#[derive(Debug, Clone)]
pub(crate) struct Permutation {
    // Maps a witness to the wires that it is associated to.
    pub(crate) witness_map: HashMap<Witness, Vec<WireData>>,
}

impl Permutation {
    /// Creates a Permutation struct with an expected capacity of zero.
    pub(crate) fn new() -> Permutation {
        Permutation::with_capacity(0)
    }

    /// Creates a Permutation struct with an expected capacity of `n`.
    pub(crate) fn with_capacity(size: usize) -> Permutation {
        Permutation {
            witness_map: HashMap::with_capacity(size),
        }
    }

    /// Creates a new [`Witness`] by incrementing the index of the
    /// `witness_map`.
    ///
    /// This is correct as whenever we add a new [`Witness`] into the system It
    /// is always allocated in the `witness_map`.
    pub(crate) fn new_witness(&mut self) -> Witness {
        // Generate the Witness
        let var = Witness::new(self.witness_map.keys().len());

        // Allocate space for the Witness on the witness_map
        // Each vector is initialized with a capacity of 16.
        // This number is a best guess estimate.
        self.witness_map.insert(var, Vec::with_capacity(16usize));

        var
    }

    /// Checks that the [`Witness`]s are valid by determining if they have been
    /// added to the system
    fn valid_witnesses(&self, witnesses: &[Witness]) -> bool {
        witnesses
            .iter()
            .all(|var| self.witness_map.contains_key(var))
    }

    /// Maps a set of [`Witness`]s (a,b,c,d) to a set of [`Wire`](WireData)s
    /// (left, right, out, fourth) with the corresponding gate index
    pub fn add_witnesses_to_map<T: Into<Witness>>(
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

        // Map each witness to the wire it is associated with
        // This essentially tells us that:
        self.add_witness_to_map(a.into(), left);
        self.add_witness_to_map(b.into(), right);
        self.add_witness_to_map(c.into(), output);
        self.add_witness_to_map(d.into(), fourth);
    }

    pub(crate) fn add_witness_to_map<T: Into<Witness> + Copy>(
        &mut self,
        var: T,
        wire_data: WireData,
    ) {
        assert!(self.valid_witnesses(&[var.into()]));

        // Since we always allocate space for the Vec of WireData when a
        // Witness is added to the witness_map, this should never fail
        let vec_wire_data = self.witness_map.get_mut(&var.into()).unwrap();
        vec_wire_data.push(wire_data);
    }

    // Performs shift by one permutation and computes sigma_1, sigma_2 and
    // sigma_3, sigma_4 permutations from the witness maps
    pub(super) fn compute_sigma_permutations(
        &mut self,
        n: usize,
    ) -> [Vec<WireData>; 4] {
        let sigma_1: Vec<_> = (0..n).map(WireData::Left).collect();
        let sigma_2: Vec<_> = (0..n).map(WireData::Right).collect();
        let sigma_3: Vec<_> = (0..n).map(WireData::Output).collect();
        let sigma_4: Vec<_> = (0..n).map(WireData::Fourth).collect();

        let mut sigmas = [sigma_1, sigma_2, sigma_3, sigma_4];

        for (_, wire_data) in self.witness_map.iter() {
            // Gets the data for each wire associated with this witness
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
        fft: &Fft<BlsScalar>,
    ) -> [Polynomial; 4] {
        // Compute sigma mappings
        let sigmas = self.compute_sigma_permutations(n);

        assert_eq!(sigmas[0].len(), n);
        assert_eq!(sigmas[1].len(), n);
        assert_eq!(sigmas[2].len(), n);
        assert_eq!(sigmas[3].len(), n);

        // define the sigma permutations using two non quadratic residues
        let mut s_sigma_1 = ZeroPoly::new(
            self.compute_permutation_lagrange(&sigmas[0], domain),
        );
        let mut s_sigma_2 = ZeroPoly::new(
            self.compute_permutation_lagrange(&sigmas[1], domain),
        );
        let mut s_sigma_3 = ZeroPoly::new(
            self.compute_permutation_lagrange(&sigmas[2], domain),
        );
        let mut s_sigma_4 = ZeroPoly::new(
            self.compute_permutation_lagrange(&sigmas[3], domain),
        );

        fft.idft(&mut s_sigma_1);
        fft.idft(&mut s_sigma_2);
        fft.idft(&mut s_sigma_3);
        fft.idft(&mut s_sigma_4);

        let s_sigma_1_poly = Polynomial::from_coefficients_vec(s_sigma_1.0);
        let s_sigma_2_poly = Polynomial::from_coefficients_vec(s_sigma_2.0);
        let s_sigma_3_poly = Polynomial::from_coefficients_vec(s_sigma_3.0);
        let s_sigma_4_poly = Polynomial::from_coefficients_vec(s_sigma_4.0);

        [
            s_sigma_1_poly,
            s_sigma_2_poly,
            s_sigma_3_poly,
            s_sigma_4_poly,
        ]
    }

    // Uses a rayon multizip to allow more code flexibility while remaining
    // parallelizable. This can be adapted into a general product argument
    // for any number of wires.
    pub(crate) fn compute_permutation_vec(
        &self,
        domain: &EvaluationDomain,
        fft: &Fft<BlsScalar>,
        wires: [&[BlsScalar]; 4],
        beta: &BlsScalar,
        gamma: &BlsScalar,
        mut sigma_polys: [ZeroPoly<BlsScalar>; 4],
    ) -> Vec<BlsScalar> {
        let n = domain.size();

        // Constants defining cosets H, k1H, k2H, etc
        let ks = vec![BlsScalar::one(), K1, K2, K3];

        // Transpose wires and sigma values to get "rows" in the form [a_w_i,
        // b_w_i, c_w_i, ... ] where each row contains the wire and sigma
        // values for a single gate
        let gatewise_wires = izip!(wires[0], wires[1], wires[2], wires[3])
            .map(|(w0, w1, w2, w3)| vec![w0, w1, w2, w3]);

        let gatewise_sigmas: Vec<Vec<BlsScalar>> = sigma_polys
            .iter_mut()
            .map(|sigma| {
                fft.dft(sigma);
                sigma.0.clone()
            })
            .collect();
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

        z
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::fft::Polynomial;
    use rand_core::OsRng;
    use zero_bls12_381::Fr as BlsScalar;
    use zero_kzg::Polynomial as ZeroPoly;

    #[allow(dead_code)]
    fn compute_fast_permutation_poly(
        domain: &EvaluationDomain,
        a_w: &[BlsScalar],
        b_w: &[BlsScalar],
        c_w: &[BlsScalar],
        d_w: &[BlsScalar],
        beta: &BlsScalar,
        gamma: &BlsScalar,
        (s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly): (
            &Polynomial,
            &Polynomial,
            &Polynomial,
            &Polynomial,
        ),
    ) -> Vec<BlsScalar> {
        let n = domain.size();
        let k = n.trailing_zeros();
        let fft = Fft::new(k as usize);

        // Compute beta * roots
        let common_roots: Vec<BlsScalar> =
            domain.elements().map(|root| root * beta).collect();

        let mut s_sigma_1_poly = ZeroPoly::new(s_sigma_1_poly.coeffs.clone());
        let mut s_sigma_2_poly = ZeroPoly::new(s_sigma_2_poly.coeffs.clone());
        let mut s_sigma_3_poly = ZeroPoly::new(s_sigma_3_poly.coeffs.clone());
        let mut s_sigma_4_poly = ZeroPoly::new(s_sigma_4_poly.coeffs.clone());

        fft.dft(&mut s_sigma_1_poly);
        fft.dft(&mut s_sigma_2_poly);
        fft.dft(&mut s_sigma_3_poly);
        fft.dft(&mut s_sigma_4_poly);

        let s_sigma_1_mapping = s_sigma_1_poly.0;
        let s_sigma_2_mapping = s_sigma_2_poly.0;
        let s_sigma_3_mapping = s_sigma_3_poly.0;
        let s_sigma_4_mapping = s_sigma_4_poly.0;

        // Compute beta * sigma polynomials
        let beta_s_sigma_1: Vec<_> =
            s_sigma_1_mapping.iter().map(|sigma| sigma * beta).collect();
        let beta_s_sigma_2: Vec<_> =
            s_sigma_2_mapping.iter().map(|sigma| sigma * beta).collect();
        let beta_s_sigma_3: Vec<_> =
            s_sigma_3_mapping.iter().map(|sigma| sigma * beta).collect();
        let beta_s_sigma_4: Vec<_> =
            s_sigma_4_mapping.iter().map(|sigma| sigma * beta).collect();

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
        let a_w_gamma: Vec<_> = a_w.iter().map(|a_w| a_w + gamma).collect();

        // Compute right_wire + gamma
        let b_w_gamma: Vec<_> = b_w.iter().map(|b_w| b_w + gamma).collect();

        // Compute out_wire + gamma
        let c_w_gamma: Vec<_> = c_w.iter().map(|c_w| c_w + gamma).collect();

        // Compute fourth_wire + gamma
        let d_w_gamma: Vec<_> = d_w.iter().map(|d_w| d_w + gamma).collect();

        // Compute 6 accumulator components
        // Parallelizable
        let accumulator_components_without_l1: Vec<_> = izip!(
            a_w_gamma,
            b_w_gamma,
            c_w_gamma,
            d_w_gamma,
            common_roots,
            beta_roots_k1,
            beta_roots_k2,
            beta_roots_k3,
            beta_s_sigma_1,
            beta_s_sigma_2,
            beta_s_sigma_3,
            beta_s_sigma_4,
        )
        .map(
            |(
                a_w_gamma,
                b_w_gamma,
                c_w_gamma,
                d_w_gamma,
                beta_root,
                beta_root_k1,
                beta_root_k2,
                beta_root_k3,
                beta_s_sigma_1,
                beta_s_sigma_2,
                beta_s_sigma_3,
                beta_s_sigma_4,
            )| {
                // w_j + beta * root^j-1 + gamma
                let ac1 = a_w_gamma + beta_root;

                // w_{n+j} + beta * K1 * root^j-1 + gamma
                let ac2 = b_w_gamma + beta_root_k1;

                // w_{2n+j} + beta * K2 * root^j-1 + gamma
                let ac3 = c_w_gamma + beta_root_k2;

                // w_{3n+j} + beta * K3 * root^j-1 + gamma
                let ac4 = d_w_gamma + beta_root_k3;

                // 1 / w_j + beta * sigma(j) + gamma
                let ac5 = (a_w_gamma + beta_s_sigma_1).invert().unwrap();

                // 1 / w_{n+j} + beta * sigma(n+j) + gamma
                let ac6 = (b_w_gamma + beta_s_sigma_2).invert().unwrap();

                // 1 / w_{2n+j} + beta * sigma(2n+j) + gamma
                let ac7 = (c_w_gamma + beta_s_sigma_3).invert().unwrap();

                // 1 / w_{3n+j} + beta * sigma(3n+j) + gamma
                let ac8 = (d_w_gamma + beta_s_sigma_4).invert().unwrap();

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
        a_w: I,
        b_w: I,
        c_w: I,
        d_w: I,
        beta: &BlsScalar,
        gamma: &BlsScalar,
        (s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly): (
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
        let k = n.trailing_zeros();
        let fft = Fft::new(k as usize);

        let mut s_sigma_1_poly = ZeroPoly::new(s_sigma_1_poly.coeffs.clone());
        let mut s_sigma_2_poly = ZeroPoly::new(s_sigma_2_poly.coeffs.clone());
        let mut s_sigma_3_poly = ZeroPoly::new(s_sigma_3_poly.coeffs.clone());
        let mut s_sigma_4_poly = ZeroPoly::new(s_sigma_4_poly.coeffs.clone());

        fft.dft(&mut s_sigma_1_poly);
        fft.dft(&mut s_sigma_2_poly);
        fft.dft(&mut s_sigma_3_poly);
        fft.dft(&mut s_sigma_4_poly);

        let s_sigma_1_mapping = s_sigma_1_poly.0;
        let s_sigma_2_mapping = s_sigma_2_poly.0;
        let s_sigma_3_mapping = s_sigma_3_poly.0;
        let s_sigma_4_mapping = s_sigma_4_poly.0;

        // Compute beta * sigma polynomials
        let beta_s_sigma_1_iter =
            s_sigma_1_mapping.iter().map(|sigma| *sigma * beta);
        let beta_s_sigma_2_iter =
            s_sigma_2_mapping.iter().map(|sigma| *sigma * beta);
        let beta_s_sigma_3_iter =
            s_sigma_3_mapping.iter().map(|sigma| *sigma * beta);
        let beta_s_sigma_4_iter =
            s_sigma_4_mapping.iter().map(|sigma| *sigma * beta);

        // Compute beta * roots
        let beta_roots_iter = domain.elements().map(|root| root * beta);

        // Compute beta * roots * K1
        let beta_roots_k1_iter = domain.elements().map(|root| K1 * beta * root);

        // Compute beta * roots * K2
        let beta_roots_k2_iter = domain.elements().map(|root| K2 * beta * root);

        // Compute beta * roots * K3
        let beta_roots_k3_iter = domain.elements().map(|root| K3 * beta * root);

        // Compute left_wire + gamma
        let a_w_gamma: Vec<_> = a_w.map(|w| w + gamma).collect();

        // Compute right_wire + gamma
        let b_w_gamma: Vec<_> = b_w.map(|w| w + gamma).collect();

        // Compute out_wire + gamma
        let c_w_gamma: Vec<_> = c_w.map(|w| w + gamma).collect();

        // Compute fourth_wire + gamma
        let d_w_gamma: Vec<_> = d_w.map(|w| w + gamma).collect();

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
            a_w_gamma,
            b_w_gamma,
            c_w_gamma,
            d_w_gamma,
            beta_root,
            beta_root_k1,
            beta_root_k2,
            beta_root_k3,
        ) in izip!(
            a_w_gamma.iter(),
            b_w_gamma.iter(),
            c_w_gamma.iter(),
            d_w_gamma.iter(),
            beta_roots_iter,
            beta_roots_k1_iter,
            beta_roots_k2_iter,
            beta_roots_k3_iter,
        ) {
            // (a_w + beta * root + gamma)
            let prod_a = beta_root + a_w_gamma;

            // (b_w + beta * root * k_1 + gamma)
            let prod_b = beta_root_k1 + b_w_gamma;

            // (c_w + beta * root * k_2 + gamma)
            let prod_c = beta_root_k2 + c_w_gamma;

            // (d_w + beta * root * k_3 + gamma)
            let prod_d = beta_root_k3 + d_w_gamma;

            let mut prod = prod_a * prod_b * prod_c * prod_d;

            numerator_partial_components.push(prod);

            prod *= numerator_coefficients.last().unwrap();

            numerator_coefficients.push(prod);
        }

        // Compute denominator coefficients
        for (
            a_w_gamma,
            b_w_gamma,
            c_w_gamma,
            d_w_gamma,
            beta_s_sigma_1,
            beta_s_sigma_2,
            beta_s_sigma_3,
            beta_s_sigma_4,
        ) in izip!(
            a_w_gamma,
            b_w_gamma,
            c_w_gamma,
            d_w_gamma,
            beta_s_sigma_1_iter,
            beta_s_sigma_2_iter,
            beta_s_sigma_3_iter,
            beta_s_sigma_4_iter,
        ) {
            // (a_w + beta * s_sigma_1 + gamma)
            let prod_a = beta_s_sigma_1 + a_w_gamma;

            // (b_w + beta * s_sigma_2 + gamma)
            let prod_b = beta_s_sigma_2 + b_w_gamma;

            // (c_w + beta * s_sigma_3 + gamma)
            let prod_c = beta_s_sigma_3 + c_w_gamma;

            // (d_w + beta * s_sigma_4 + gamma)
            let prod_d = beta_s_sigma_4 + d_w_gamma;

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
    fn test_permutation_format() {
        let mut perm: Permutation = Permutation::new();

        let num_witnesses = 10u8;
        for i in 0..num_witnesses {
            let var = perm.new_witness();
            assert_eq!(var.index(), i as usize);
            assert_eq!(perm.witness_map.len(), (i as usize) + 1);
        }

        let var_one = perm.new_witness();
        let var_two = perm.new_witness();
        let var_three = perm.new_witness();

        let gate_size = 100;
        for i in 0..gate_size {
            perm.add_witnesses_to_map(var_one, var_one, var_two, var_three, i);
        }

        // Check all gate_indices are valid
        for (_, wire_data) in perm.witness_map.iter() {
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

        let var_zero = perm.new_witness();
        let var_two = perm.new_witness();
        let var_three = perm.new_witness();
        let var_four = perm.new_witness();
        let var_five = perm.new_witness();
        let var_six = perm.new_witness();
        let var_seven = perm.new_witness();
        let var_eight = perm.new_witness();
        let var_nine = perm.new_witness();

        let k = 2;
        let num_wire_mappings = 4;

        // Add four wire mappings
        perm.add_witnesses_to_map(var_zero, var_zero, var_five, var_nine, 0);
        perm.add_witnesses_to_map(var_zero, var_two, var_six, var_nine, 1);
        perm.add_witnesses_to_map(var_zero, var_three, var_seven, var_nine, 2);
        perm.add_witnesses_to_map(var_zero, var_four, var_eight, var_nine, 3);

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
        s_sigma_1 = {R0, L2, L3, L0}
        s_sigma_2 = {L1, R1, R2, R3}
        s_sigma_3 = {O0, O1, O2, O3}
        s_sigma_4 = {F1, F2, F3, F0}
        */
        let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
        let s_sigma_1 = &sigmas[0];
        let s_sigma_2 = &sigmas[1];
        let s_sigma_3 = &sigmas[2];
        let s_sigma_4 = &sigmas[3];

        // Check the left sigma polynomial
        assert_eq!(s_sigma_1[0], WireData::Right(0));
        assert_eq!(s_sigma_1[1], WireData::Left(2));
        assert_eq!(s_sigma_1[2], WireData::Left(3));
        assert_eq!(s_sigma_1[3], WireData::Left(0));

        // Check the right sigma polynomial
        assert_eq!(s_sigma_2[0], WireData::Left(1));
        assert_eq!(s_sigma_2[1], WireData::Right(1));
        assert_eq!(s_sigma_2[2], WireData::Right(2));
        assert_eq!(s_sigma_2[3], WireData::Right(3));

        // Check the output sigma polynomial
        assert_eq!(s_sigma_3[0], WireData::Output(0));
        assert_eq!(s_sigma_3[1], WireData::Output(1));
        assert_eq!(s_sigma_3[2], WireData::Output(2));
        assert_eq!(s_sigma_3[3], WireData::Output(3));

        // Check the output sigma polynomial
        assert_eq!(s_sigma_4[0], WireData::Fourth(1));
        assert_eq!(s_sigma_4[1], WireData::Fourth(2));
        assert_eq!(s_sigma_4[2], WireData::Fourth(3));
        assert_eq!(s_sigma_4[3], WireData::Fourth(0));

        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let fft = Fft::<BlsScalar>::new(k);
        let w = domain.group_gen;
        let w_squared = w.pow(2);
        let w_cubed = w.pow(3);

        // Check the left sigmas have been encoded properly
        // s_sigma_1 = {R0, L2, L3, L0}
        // Should turn into {1 * K1, w^2, w^3, 1}
        let encoded_s_sigma_1 =
            perm.compute_permutation_lagrange(s_sigma_1, &domain);
        assert_eq!(encoded_s_sigma_1[0], BlsScalar::one() * K1);
        assert_eq!(encoded_s_sigma_1[1], w_squared);
        assert_eq!(encoded_s_sigma_1[2], w_cubed);
        assert_eq!(encoded_s_sigma_1[3], BlsScalar::one());

        // Check the right sigmas have been encoded properly
        // s_sigma_2 = {L1, R1, R2, R3}
        // Should turn into {w, w * K1, w^2 * K1, w^3 * K1}
        let encoded_s_sigma_2 =
            perm.compute_permutation_lagrange(s_sigma_2, &domain);
        assert_eq!(encoded_s_sigma_2[0], w);
        assert_eq!(encoded_s_sigma_2[1], w * K1);
        assert_eq!(encoded_s_sigma_2[2], w_squared * K1);
        assert_eq!(encoded_s_sigma_2[3], w_cubed * K1);

        // Check the output sigmas have been encoded properly
        // s_sigma_3 = {O0, O1, O2, O3}
        // Should turn into {1 * K2, w * K2, w^2 * K2, w^3 * K2}
        let encoded_s_sigma_3 =
            perm.compute_permutation_lagrange(s_sigma_3, &domain);
        assert_eq!(encoded_s_sigma_3[0], BlsScalar::one() * K2);
        assert_eq!(encoded_s_sigma_3[1], w * K2);
        assert_eq!(encoded_s_sigma_3[2], w_squared * K2);
        assert_eq!(encoded_s_sigma_3[3], w_cubed * K2);

        // Check the fourth sigmas have been encoded properly
        // s_sigma_4 = {F1, F2, F3, F0}
        // Should turn into {w * K3, w^2 * K3, w^3 * K3, 1 * K3}
        let encoded_s_sigma_4 =
            perm.compute_permutation_lagrange(s_sigma_4, &domain);
        assert_eq!(encoded_s_sigma_4[0], w * K3);
        assert_eq!(encoded_s_sigma_4[1], w_squared * K3);
        assert_eq!(encoded_s_sigma_4[2], w_cubed * K3);
        assert_eq!(encoded_s_sigma_4[3], K3);

        let a_w = vec![
            BlsScalar::from(2),
            BlsScalar::from(2),
            BlsScalar::from(2),
            BlsScalar::from(2),
        ];
        let b_w = vec![
            BlsScalar::from(2),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];
        let c_w = vec![
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];
        let d_w = vec![
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];

        test_correct_permutation_poly(
            num_wire_mappings,
            perm,
            &domain,
            &fft,
            a_w,
            b_w,
            c_w,
            d_w,
        );
    }

    #[test]
    fn test_permutation_compute_sigmas() {
        let mut perm: Permutation = Permutation::new();

        let var_one = perm.new_witness();
        let var_two = perm.new_witness();
        let var_three = perm.new_witness();
        let var_four = perm.new_witness();

        let num_wire_mappings = 4;

        // Add four wire mappings
        perm.add_witnesses_to_map(var_one, var_one, var_two, var_four, 0);
        perm.add_witnesses_to_map(var_two, var_one, var_two, var_four, 1);
        perm.add_witnesses_to_map(var_three, var_three, var_one, var_four, 2);
        perm.add_witnesses_to_map(var_two, var_one, var_three, var_four, 3);

        /*
        Below is a sketch of the map created by adding the specific witnesses into the map
        var_one : {L0,R0, R1, O2, R3 }
        var_two : {O0, L1, O1, L3}
        var_three : {L2, R2, O3}
        var_four : {F0, F1, F2, F3}
        s_sigma_1 : {0,1,2,3} -> {R0,O1,R2,O0}
        s_sigma_2 : {0,1,2,3} -> {R1, O2, O3, L0}
        s_sigma_3 : {0,1,2,3} -> {L1, L3, R3, L2}
        s_sigma_4 : {0,1,2,3} -> {F1, F2, F3, F0}
        */
        let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
        let s_sigma_1 = &sigmas[0];
        let s_sigma_2 = &sigmas[1];
        let s_sigma_3 = &sigmas[2];
        let s_sigma_4 = &sigmas[3];

        // Check the left sigma polynomial
        assert_eq!(s_sigma_1[0], WireData::Right(0));
        assert_eq!(s_sigma_1[1], WireData::Output(1));
        assert_eq!(s_sigma_1[2], WireData::Right(2));
        assert_eq!(s_sigma_1[3], WireData::Output(0));

        // Check the right sigma polynomial
        assert_eq!(s_sigma_2[0], WireData::Right(1));
        assert_eq!(s_sigma_2[1], WireData::Output(2));
        assert_eq!(s_sigma_2[2], WireData::Output(3));
        assert_eq!(s_sigma_2[3], WireData::Left(0));

        // Check the output sigma polynomial
        assert_eq!(s_sigma_3[0], WireData::Left(1));
        assert_eq!(s_sigma_3[1], WireData::Left(3));
        assert_eq!(s_sigma_3[2], WireData::Right(3));
        assert_eq!(s_sigma_3[3], WireData::Left(2));

        // Check the fourth sigma polynomial
        assert_eq!(s_sigma_4[0], WireData::Fourth(1));
        assert_eq!(s_sigma_4[1], WireData::Fourth(2));
        assert_eq!(s_sigma_4[2], WireData::Fourth(3));
        assert_eq!(s_sigma_4[3], WireData::Fourth(0));

        /*
        Check that the unique encodings of the sigma polynomials have been computed properly
        s_sigma_1 : {R0,O1,R2,O0}
            When encoded using w, K1,K2,K3 we have {1 * K1, w * K2, w^2 * K1, 1 * K2}
        s_sigma_2 : {R1, O2, O3, L0}
            When encoded using w, K1,K2,K3 we have {w * K1, w^2 * K2, w^3 * K2, 1}
        s_sigma_3 : {L1, L3, R3, L2}
            When encoded using w, K1, K2,K3 we have {w, w^3 , w^3 * K1, w^2}
        s_sigma_4 : {0,1,2,3} -> {F1, F2, F3, F0}
            When encoded using w, K1, K2,K3 we have {w * K3, w^2 * K3, w^3 * K3, 1 * K3}
        */
        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let w = domain.group_gen;
        let w_squared = w.pow(2);
        let w_cubed = w.pow(3);
        // check the left sigmas have been encoded properly
        let encoded_s_sigma_1 =
            perm.compute_permutation_lagrange(s_sigma_1, &domain);
        assert_eq!(encoded_s_sigma_1[0], K1);
        assert_eq!(encoded_s_sigma_1[1], w * K2);
        assert_eq!(encoded_s_sigma_1[2], w_squared * K1);
        assert_eq!(encoded_s_sigma_1[3], BlsScalar::one() * K2);

        // check the right sigmas have been encoded properly
        let encoded_s_sigma_2 =
            perm.compute_permutation_lagrange(s_sigma_2, &domain);
        assert_eq!(encoded_s_sigma_2[0], w * K1);
        assert_eq!(encoded_s_sigma_2[1], w_squared * K2);
        assert_eq!(encoded_s_sigma_2[2], w_cubed * K2);
        assert_eq!(encoded_s_sigma_2[3], BlsScalar::one());

        // check the output sigmas have been encoded properly
        let encoded_s_sigma_3 =
            perm.compute_permutation_lagrange(s_sigma_3, &domain);
        assert_eq!(encoded_s_sigma_3[0], w);
        assert_eq!(encoded_s_sigma_3[1], w_cubed);
        assert_eq!(encoded_s_sigma_3[2], w_cubed * K1);
        assert_eq!(encoded_s_sigma_3[3], w_squared);

        // check the fourth sigmas have been encoded properly
        let encoded_s_sigma_4 =
            perm.compute_permutation_lagrange(s_sigma_4, &domain);
        assert_eq!(encoded_s_sigma_4[0], w * K3);
        assert_eq!(encoded_s_sigma_4[1], w_squared * K3);
        assert_eq!(encoded_s_sigma_4[2], w_cubed * K3);
        assert_eq!(encoded_s_sigma_4[3], K3);
    }

    #[test]
    fn test_basic_slow_permutation_poly() {
        let k = 1;
        let num_wire_mappings = 2;
        let mut perm = Permutation::new();
        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let fft = Fft::<BlsScalar>::new(k);

        let var_one = perm.new_witness();
        let var_two = perm.new_witness();
        let var_three = perm.new_witness();
        let var_four = perm.new_witness();

        perm.add_witnesses_to_map(var_one, var_two, var_three, var_four, 0);
        perm.add_witnesses_to_map(var_three, var_two, var_one, var_four, 1);

        let a_w: Vec<_> = vec![BlsScalar::one(), BlsScalar::from(3)];
        let b_w: Vec<_> = vec![BlsScalar::from(2), BlsScalar::from(2)];
        let c_w: Vec<_> = vec![BlsScalar::from(3), BlsScalar::one()];
        let d_w: Vec<_> = vec![BlsScalar::one(), BlsScalar::one()];

        test_correct_permutation_poly(
            num_wire_mappings,
            perm,
            &domain,
            &fft,
            a_w,
            b_w,
            c_w,
            d_w,
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
        fft: &Fft<BlsScalar>,
        a_w: Vec<BlsScalar>,
        b_w: Vec<BlsScalar>,
        c_w: Vec<BlsScalar>,
        d_w: Vec<BlsScalar>,
    ) {
        // 0. Generate beta and gamma challenges
        //
        let beta = BlsScalar::random(&mut OsRng);
        let gamma = BlsScalar::random(&mut OsRng);
        assert_ne!(gamma, beta);

        //1. Compute the permutation polynomial using both methods
        let [s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly] =
            perm.compute_sigma_polynomials(n, domain, fft);
        let (z_vec, numerator_components, denominator_components) =
            compute_slow_permutation_poly(
                domain,
                a_w.clone().into_iter(),
                b_w.clone().into_iter(),
                c_w.clone().into_iter(),
                d_w.clone().into_iter(),
                &beta,
                &gamma,
                (
                    &s_sigma_1_poly,
                    &s_sigma_2_poly,
                    &s_sigma_3_poly,
                    &s_sigma_4_poly,
                ),
            );

        let fast_z_vec = compute_fast_permutation_poly(
            domain,
            &a_w,
            &b_w,
            &c_w,
            &d_w,
            &beta,
            &gamma,
            (
                &s_sigma_1_poly,
                &s_sigma_2_poly,
                &s_sigma_3_poly,
                &s_sigma_4_poly,
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
        let mut z_vec = ZeroPoly::new(z_vec);
        fft.idft(&mut z_vec);
        let z_poly = Polynomial::from_coefficients_vec(z_vec.0);
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
        let mut shifted_z = ZeroPoly::new(shift_poly_by_one(fast_z_vec));
        fft.idft(&mut shifted_z);
        let shifted_z_poly = Polynomial::from_coefficients_vec(shifted_z.0);
        for element in domain.elements() {
            let z_eval = z_poly.evaluate(&(element * domain.group_gen));
            let shifted_z_eval = shifted_z_poly.evaluate(&element);

            assert_eq!(z_eval, shifted_z_eval)
        }
    }
}
