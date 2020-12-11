use crate::fft::{EvaluationDomain, Polynomial};
use dusk_bls12_381::BlsScalar;
use itertools::izip;
use rayon::iter::*;

/// This file constructs an accumulator polynomial similar to
/// plonk's permutation polynomial. Checking it at adjacent values allows
/// us to check that the "randomized differences" between values are what we'd
/// expect from a multiset whose elements are from the lookup table

pub struct Plookup {
    table: Vec<BlsScalar>,
    queries: Vec<BlsScalar>,
}

impl Plookup {

	/// Compress lookup values 
	pub fn compress_zeta(
			wires: (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
			parameter: &BlsScalar
			) -> BlsScalar {
		let powers = util::powers_of(&parameter, 4);
        let c_l: Vec<BlsScalars> = wires
            .iter()
            .zip(powers.iter())
            .map(|(poly, challenge)| poly * challenge)
            .sum();
	}
	
    // These are the formulas for the irreducible factors used in the product argument
    fn plookup_table_irreducible(
        w: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> BlsScalar {
        (BlsScalar::one() + beta) * (gamma + w)
    }

    fn plookup_random_difference(
        t: &BlsScalar,
        t_next: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> BlsScalar {
        gamma * (BlsScalar::one() + beta) + t + (beta * t_next)
    }

    fn multizip_compute_plookup_product(
        domain: &EvaluationDomain,
        queries: &Vec<BlsScalar>,
        table: &Vec<BlsScalar>,
        sorted: (&[BlsScalar], &[BlsScalar]),
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> Vec<BlsScalar> {

        let d = domain.size();

        assert!(queries.len() + 1 == domain.size());
        assert!(table.len() == domain.size());
        assert!(sorted.0.len() == domain.size());
        assert!(sorted.1.len() == domain.size());

        // To Do: add assertions that the queries, table, and sorteds are correct length

        // the randomized differences need to be able to access the "next" element
        // so we shift them by one
        let table_next: Vec<BlsScalar> = [&table[1..], &[table[0]]].concat();
        let sorted1 = sorted.0;
        let sorted1_next: Vec<BlsScalar> = [&sorted1[1..], &[sorted1[0]]].concat();
        let sorted2 = sorted.1;
        let sorted2_next: Vec<BlsScalar> = [&sorted2[1..], &[sorted2[0]]].concat();

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
            .collect::<Vec<BlsScalar>>();

        let mut plookup_z_coefficients = Vec::with_capacity(d);

        // First element is one
        let mut state = BlsScalar::one();
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
    use crate::fft::Evaluations;

    #[test]
    fn test_plookup_prove_verify() {
        let mut rng = rand::thread_rng();

        let domain = EvaluationDomain::new(100).unwrap();
        let n = domain.size() - 1;
        let g_inv = domain.group_gen_inv;

        // the indexing below differs from Plookup paper: we will use 0..n
        //   where the paper uses 1..n+1

        // generate random table and queries of correct size
        // in practice you would pad the table and queries to get the correct size
        let (table, queries) = random_table_and_queries(domain.size());

        // concatenate and sort the table and queries
        let mut concat_table_and_queries = [&queries[..], &table[..]].concat();
        concat_table_and_queries.sort();

        // split big sorted list into two parts that overlap by one element
        let sorted_lo = &concat_table_and_queries[0..n+1];
        let sorted_hi = &concat_table_and_queries[n..];

        // create the h1(x), h2(x) polynomials from sorted_lo and sorted_hi in evaluation form
        let h1 = Evaluations::from_vec_and_domain(sorted_lo.to_vec(), domain);
        let h2 = Evaluations::from_vec_and_domain(sorted_hi.to_vec(), domain);

        // create the shifted h1(gx), and h2(gx) polynomials by rotating the evaluations
        let h1g = Evaluations::from_vec_and_domain([&sorted_lo[1..n+1], &[sorted_lo[0]]].concat(), domain);
        let h2g = Evaluations::from_vec_and_domain([&sorted_hi[1..n+1], &[sorted_hi[0]]].concat(), domain);

        // create the polynomial representing the queries in evaluation form
        let f = Evaluations::from_vec_and_domain(queries.clone(), domain);

        // create the polynomials representing the table and shifted table in evaluation form
        let t = Evaluations::from_vec_and_domain(table.clone(), domain);
        let tg = Evaluations::from_vec_and_domain([&table[1..n+1], &[table[0]]].concat(), domain);

        // create L1 Lagrange polynomial in evaluation form
        let mut one_followed_by_zeros = vec![BlsScalar::one()];
        one_followed_by_zeros.extend(vec![BlsScalar::zero(); domain.size()-1]);
        let l1 = Evaluations::from_vec_and_domain(one_followed_by_zeros, domain);

        // create Ln Lagrange polynomial in evaluation form
        let mut zeros_followed_by_one = vec![BlsScalar::zero(); domain.size()-1];
        zeros_followed_by_one.push(BlsScalar::one());
        let ln = Evaluations::from_vec_and_domain(zeros_followed_by_one, domain);

        // get random parameters beta and gamma
        let beta_scalar = BlsScalar::random(&mut rng);
        let gamma_scalar = BlsScalar::random(&mut rng);

        // convert random parameters to constant polynomials in evaluation form
        let gamma = Evaluations::from_vec_and_domain(vec![gamma_scalar; domain.size()], domain);
        let beta = Evaluations::from_vec_and_domain(vec![beta_scalar; domain.size()], domain);

        // create constant polynomials for zero and one in evaluation form 
        let zero = Evaluations::from_vec_and_domain(vec![BlsScalar::zero(); domain.size()], domain);
        let one = Evaluations::from_vec_and_domain(vec![BlsScalar::one(); domain.size()], domain);

        let z_values = Plookup::multizip_compute_plookup_product(
            &domain,
            &queries,
            &table,
            (&sorted_lo, &sorted_hi),
            &beta_scalar,
            &gamma_scalar,
        );

        // create the Z polynomial in evaluation form
        let z = Evaluations::from_vec_and_domain(z_values.clone(), domain);
        let zg = Evaluations::from_vec_and_domain([&z_values[1..n+1], &[z_values[0]]].concat(), domain);

        // g^n = g^(-1) 
        let x_minus_g_to_n = Evaluations::from_vec_and_domain(
            domain.fft(
                &Polynomial::from_coefficients_vec(
                   vec![-g_inv, BlsScalar::one()]
                ).coeffs
            ),
            domain
        );

        // for convenience
        let one_plus_beta = &one + &beta;
        let gamma_times_one_plus_beta = &gamma * &one_plus_beta;

        // Verifier checks

        // a: check that the first value of Z is 1
        assert!(&l1 * &(&z - &one) == zero);

        // b: check the left and right sides of the "big equation" are equal

        // we use g^n rather than g^(n+1), and L_n rather than L_(n+1) because of the 
        let left = &(&(&(&x_minus_g_to_n * &z) * &one_plus_beta) * &(&gamma + &f)) * &(&(&gamma_times_one_plus_beta + &t) + &(&beta * &tg));
        let right = &(&(&x_minus_g_to_n * &zg) * &(&(&gamma_times_one_plus_beta + &h1) + &(&beta*&h1g))) * &(&(&gamma_times_one_plus_beta + &h2) + &(&beta * &h2g));
        
        assert!(left == right);
        
        // c: check that the last element of h1 is the first element of h2 
        assert!(&ln * &(&h1 - &h2g) == zero);

        // d: check that the last element of Z is 1
        assert!(&ln * &(&z - &one) == zero);
    }

    fn random_table_and_queries(n: usize) -> (Vec<BlsScalar>, Vec<BlsScalar>) {
        let mut rng = rand::thread_rng();

        // create a table of random scalars
        let mut random_table: Vec<BlsScalar> = (0..n).into_iter().map(|_i| BlsScalar::random(&mut rng)).collect();
        random_table.sort();

        // create a table of queries from the table
        let random_queries: Vec<BlsScalar> = (0..n-1).into_iter().map(|_i| random_table[rng.gen_range(0, n)]).collect();

        (random_table, random_queries)
    }
}
