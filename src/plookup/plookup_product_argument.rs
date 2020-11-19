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
        //&self,
        domain: &EvaluationDomain,
        queries: &Vec<Scalar>,
        table: &Vec<Scalar>,
        sorted: (&[Scalar], &[Scalar]),
        beta: &Scalar,
        gamma: &Scalar,
    ) -> Vec<Scalar> {

        let n = domain.size();

        // To Do: add assertions that the queries, table, and sorteds are correct length

        // the randomized differences need to be able to access the "next" element
        // so we shift them by one
        let table_next: Vec<Scalar> = [&table[1..n], &[table[0]]].concat();
        let sorted1 = sorted.0;
        let sorted1_next: Vec<Scalar> = [&sorted1[1..n], &[sorted1[0]]].concat();
        let sorted2 = sorted.1;
        let sorted2_next: Vec<Scalar> = [&sorted2[1..n], &[sorted2[0]]].concat();

        let plookup_accumulator = (queries, table, table_next, sorted1, sorted1_next, sorted2, sorted2_next)
            .into_par_iter()

            // Multiply up the numerator and denominator irreducibles for each gate
            //   and pair the results
            .map(|(f, t, t_next, s1, s1_next, s2, s2_next)|
                (
                    Plookup::plookup_table_irreducible(&f, beta, gamma)
                    * Plookup::plookup_random_difference(&t, &t_next, beta, gamma)
                ,
                    Plookup::plookup_random_difference(&s1, &s1_next, beta, gamma)
                    * Plookup::plookup_random_difference(&s2, &s2_next, beta, gamma)
                )
            )

            // Divide each pair to get the single scalar representing each gate
            .map(|(n, d)| n * d.invert().unwrap())

            // Collect into vector intermediary since rayon does not support `scan`
            .collect::<Vec<Scalar>>();

        let mut plookup_z_coefficients = Vec::with_capacity(n);

        // First element is one
        let mut state = Scalar::one();
        plookup_z_coefficients.push(state);

        // Accumulate by successively multiplying the scalars
        // Non-parallelizable
        for s in plookup_accumulator {
            state *= s;
            plookup_z_coefficients.push(state);
        }

        plookup_z_coefficients
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;
    use super::*;

    #[test]
    fn test_plookup_accumulator() {
        let mut rng = rand::thread_rng();

        // this should be completely randomized eventually
        // should be easy since table entries are independent of each other
        //   unlike arithmetic circuit gates

        // table is for the function that counts the number of set bits for integers 0 to 15
        let uncompressed_table = vec![
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 2),
            (4, 1),
            (5, 2),
            (6, 2),
            (7, 3),
            (8, 1),
            (9, 2),
            (10, 2),
            (11, 3),
            (12, 2),
            (13, 3),
            (14, 3),
            (15, 4),
        ];

        let alpha = Scalar::random(&mut rng);

        let mut compressed_table: Vec<Scalar> = uncompressed_table.into_iter().map(|(a, b)| Scalar::from_raw([a,0,0,0]) + alpha*Scalar([b,0,0,0])).collect();

        // although the table itself does not have to be sorted, the ordering of the concatenated lookups and table need to match
        // the ordering of the table. sorting both the same way makes sure the order matches.
        compressed_table.sort();

        let n = compressed_table.len()-1;

        let uncompressed_queries = vec![
            (2, 1),
            (7, 3),
            (2, 1),
            (4, 1),
            (8, 1),
            (15, 4),
        ];

        let mut compressed_queries: Vec<Scalar> = uncompressed_queries.into_iter().map(|(a, b)| Scalar::from_raw([a,0,0,0]) + alpha*Scalar([b,0,0,0])).collect();

        // pad lookups with last element until the length is one less than the table length
        while compressed_queries.len() < n {
            compressed_queries.push(*compressed_queries.last().unwrap());
        }
        assert!(compressed_queries.len()+1 == compressed_table.len());

        let mut big_sort = [&compressed_queries[..], &compressed_table[..]].concat();
        big_sort.sort();

        let sorted1 = &big_sort[0..n+1];
        let sorted2 = &big_sort[n..];

        assert!(sorted1[n]==sorted2[0]);
        assert!(sorted1.len() == n+1);
        assert!(sorted2.len() == n+1);

        let domain = EvaluationDomain::new(n+1).unwrap();
        let beta = Scalar::random(&mut rng);
        let gamma = Scalar::random(&mut rng);

        let mut z_coeffs = Plookup::multizip_compute_plookup_product(
            &domain,
            &compressed_queries,
            &compressed_table,
            (&sorted1, &sorted2),
            &beta,
            &gamma,
        );

        assert!(z_coeffs.last().unwrap() == &Scalar::one());
    }
}