use crate::constraint_system::{Variable, WireData, Permutation};
use crate::fft::{EvaluationDomain, Polynomial};
use dusk_bls12_381::Scalar;
use itertools::izip;
use rayon::iter::*;

/// This file constructs an accumulator polynomial similar to
/// plonk's permutation polynomial. Checking it at adjacent values allows
/// us to check that the "randomized differences" between values are what we'd
/// expect from a multiset whose elements are from the lookup table

pub struct Plookup {
    table: Vec<Scalar>,
}

impl Plookup {
    // These are the formulas for the irreducible factors used in the product argument
    fn plookup_table_irreducible(
        w: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
    ) -> Scalar {
        (Scalar::one() + beta) * (gamma + w)
    }

    fn plookup_random_difference(
        t: &Scalar,
        t_next: &Scalar,
        beta: &Scalar,
        gamma: &Scalar,
    ) -> Scalar {
        gamma * (Scalar::one() + beta) + t + (beta * t_next)
    }


    // Uses a rayon multizip to allow more code flexibility while remaining parallelizable.
    // This can be adapted into a general product argument for any number of wires, with specific formulas defined
    //   in the numerator_irreducible and denominator_irreducible functions

    fn multizip_compute_plookup_product(
        &self,
        domain: &EvaluationDomain,
        // wires: (&[Scalar], &[Scalar], &[Scalar], &[Scalar]),
        queries: &Vec<Scalar>,
        table: &Vec<Scalar>,
        sorted: (&Vec<Scalar>, &Vec<Scalar>),
        beta: &Scalar,
        gamma: &Scalar,
        // sigmas: (&Vec<Scalar>, &Vec<Scalar>, &Vec<Scalar>, &Vec<Scalar>),
    ) -> Vec<Scalar> {

        let n = domain.size();

        // the randomized differences need to be able to access the "next" element
        // so we shift them by one
        let table_next: Vec<Scalar> = [&table[1..n], &[table[0]]].concat();
        let sorted1 = sorted.0;
        let sorted1_next: Vec<Scalar> = [&sorted1[1..n], &[sorted1[0]]].concat();
        let sorted2 = sorted.1;
        let sorted2_next: Vec<Scalar> = [&sorted2[1..n], &[sorted2[0]]].concat();

        // Transpose queries, table, and sorted values to get "rows"
        // in the form [f_i, t_i, t_next_i, h1_i, h1_next_i, h2_i, h2_next_i]
        //let pointwise_polys = (queries, table, table_next,
        //                    sorted1, sorted1_next, sorted2, sorted2_next)
        //    .into_par_iter();
            //.map(|(f, t, t_n, h1, h1_n, h2, h2_n)| vec![f, t, &t_n, h1, &h1_n, h2, &h2_n]);

        // Compute all roots
        // Non-parallelizable?
        let roots: Vec<Scalar> = domain.elements().collect();

        let product_argument = (roots, queries, table, table_next, sorted1, sorted1_next, sorted2, sorted2_next)
            .into_par_iter()
            // Associate each lookup query, table, sorted value with its index
            // Actually that's a terrible explanation of it
            // This is just part of the plonk code, mutatis mutandis
            // We might be able to drop it/streamline it
            //.map(|(root, poly)| {
            //    (pointwise_root, pointwise_polys.into_par_iter())
            //})

            // Now the ith element represents index i and will have the form:
            //   (root_i, (f_i, t_i, t_next_i, h1_i, h1_next_i, h2_i, h2_next_i))
            //   which is all the information
            //   needed for a single product coefficient for a single lookup
            // Multiply up the numerator and denominator irreducibles for each gate
            //   and pair the results
            .map(|(index_root, lookup_septuple)| {
                (
                    // Numerator product
                    lookup_septuple
                        .clone()
                        .map(|(f, t, t_n, _h1, _h1_n, _h2, _h2_n)| {
                            Plookup::plookup_table_irreducible(&f, beta, gamma)
                            * Plookup::plookup_random_difference(&t, &t_n, beta, gamma)
                        })
                        .product::<Scalar>(),
                    // Denominator product
                    lookup_septuple
                        .map(|(_f, _t, _t_n, h1, h1_n, h2, h2_n)| {
                            Plookup::plookup_random_difference(&h1, &h1_n, beta, gamma)
                            * Plookup::plookup_random_difference(&h2, &h2_n, beta, gamma)
                        })
                        .product::<Scalar>(),
                )
            })
            // Divide each pair to get the single scalar representing each gate
            .map(|(n, d)| n * d.invert().unwrap())
            // Collect into vector intermediary since rayon does not support `scan`
            .collect::<Vec<Scalar>>();

        let mut plookup_z_coefficients = Vec::with_capacity(n);

        // First element is one
        let mut state = Scalar::one();
        plookup_z_coefficients.push(state);

        // Accumulate by successively multiplying the scalars
        // Non-parallelizable?
        for s in product_argument {
            state *= s;
            plookup_z_coefficients.push(state);
        }

        plookup_z_coefficients
    }
}