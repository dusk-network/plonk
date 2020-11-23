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


    fn multizip_compute_plookup_product(
        //&self,
        domain: &EvaluationDomain,
        queries: &Vec<Scalar>,
        table: &Vec<Scalar>,
        sorted: (&[Scalar], &[Scalar]),
        beta: &Scalar,
        gamma: &Scalar,
    ) -> Vec<Scalar> {

        let d = domain.size();

        assert!(queries.len() + 1 == domain.size());
        assert!(table.len() == domain.size());
        assert!(sorted.0.len() == domain.size());
        assert!(sorted.1.len() == domain.size());

        // To Do: add assertions that the queries, table, and sorteds are correct length

        // the randomized differences need to be able to access the "next" element
        // so we shift them by one
        let table_next: Vec<Scalar> = [&table[1..], &[table[0]]].concat();
        let sorted1 = sorted.0;
        let sorted1_next: Vec<Scalar> = [&sorted1[1..], &[sorted1[0]]].concat();
        let sorted2 = sorted.1;
        let sorted2_next: Vec<Scalar> = [&sorted2[1..], &[sorted2[0]]].concat();

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

        let mut plookup_z_coefficients = Vec::with_capacity(d);

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
    use crate::fft::Evaluations;

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

        let domain = EvaluationDomain::new(compressed_table.len()).unwrap();
        let n = domain.size() - 1;

        while compressed_table.len() < domain.size() {
            compressed_table.push(*compressed_table.last().unwrap());
        }

        let uncompressed_queries = vec![
            (2, 1),
            (7, 3),
            (2, 1),
            (4, 1),
            (8, 1),
            (15, 4),
        ];

        let mut compressed_queries: Vec<Scalar> = uncompressed_queries.into_iter().map(|(a, b)| Scalar::from_raw([a,0,0,0]) + alpha*Scalar([b,0,0,0])).collect();

        // pad queries with last element until the length is one less than the table length
        while compressed_queries.len() + 1 < domain.size() {
            compressed_queries.push(*compressed_queries.last().unwrap());
        }

        let mut big_sort = [&compressed_queries[..], &compressed_table[..]].concat();
        big_sort.sort();

        let sorted1 = &big_sort[0..n+1];
        let sorted2 = &big_sort[n..];

        assert!(sorted1[n] == sorted2[0]);
        assert!(sorted1.len() == domain.size());
        assert!(sorted2.len() == domain.size());

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

    #[test]
    fn test_plookup_prove_verify() {
        let n: usize = 4;
        let mut rng = rand::thread_rng();

        // generate random table and queries
        let (table, queries) = random_table_and_queries(n);

        // Prover

        // concatenate and sort the table and queries
        let mut concat_table_and_queries = [&queries[..], &table[..]].concat();
        concat_table_and_queries.sort();

        // split big sorted list into two parts that overlap by one element
        let sorted_lo = &concat_table_and_queries[0..n+1];
        let sorted_hi = &concat_table_and_queries[n..];

        let domain = EvaluationDomain::new(n+1).unwrap();
        let g = domain.group_gen;

        let h1_x = Polynomial::from_coefficients_vec(domain.ifft(&sorted_lo));
        let h1_gx = Polynomial::from_coefficients_vec(domain.ifft(&[&sorted_lo[1..n], &[sorted_lo[0]]].concat()));

        let h2_x = Polynomial::from_coefficients_vec(domain.ifft(&sorted_hi));
        let h2_gx = Polynomial::from_coefficients_vec(domain.ifft(&[&sorted_hi[1..n], &[sorted_hi[0]]].concat()));

        let f_x = Polynomial::from_coefficients_vec(domain.ifft(&queries));
        let t_x = Polynomial::from_coefficients_vec(domain.ifft(&table));
        let t_gx = Polynomial::from_coefficients_vec(domain.ifft(&[&table[1..n], &[table[0]]].concat()));

        let mut one_followed_by_zeroes = vec![Scalar::one()];
        one_followed_by_zeroes.extend(vec![Scalar::zero(); domain.size()-1]);
        let one_poly = Polynomial::from_coefficients_vec(one_followed_by_zeroes.clone());
        let beta = Scalar::random(&mut rng);
        let gamma = Scalar::random(&mut rng);

        let Z_values = Plookup::multizip_compute_plookup_product(
            &domain,
            &queries,
            &table,
            (&sorted_lo, &sorted_hi),
            &beta,
            &gamma,
        );

        assert!(Z_values[0] == Scalar::one());
        assert!(Z_values.last().unwrap() == &Scalar::one());

        let Z_x = Polynomial::from_coefficients_vec(domain.ifft(&Z_values));
        let Z_gx = Polynomial::from_coefficients_vec(domain.ifft(&[&Z_values[1..n+1], &[Z_values[0]]].concat()));

        // Verifier
        // naive verifier based on Plookup paper

        // a: check that the first value is 1
        let zero_eval = Evaluations::from_vec_and_domain(vec![Scalar::zero(); domain.size()], domain);
        let one_eval = Evaluations::from_vec_and_domain(vec![Scalar::one(); domain.size()], domain);
        let L1_eval = Evaluations::from_vec_and_domain(one_followed_by_zeroes, domain);
        let Z_eval = Evaluations::from_vec_and_domain(Z_values, domain);

        // show L_1(x) * (Z(x) - 1) = 0 on all x in H
        assert!((&L1_eval * &(&Z_eval - &one_eval)).evals == zero_eval.evals);

        // b:  
        let x_minus_g_to_n_plus_1_eval = Evaluations::from_vec_and_domain(
            domain.fft(
                &Polynomial::from_coefficients_vec(
                    vec![-g.pow(&[(n+1) as u64,0,0,0]), Scalar::one()]
                ).coeffs
            ),
            domain
        );

        let one_plus_beta_eval = Evaluations::from_vec_and_domain(vec![Scalar::one()+beta; domain.size()], domain);
        let gamma_eval = Evaluations::from_vec_and_domain(vec![gamma; domain.size()], domain);
        let beta_eval = Evaluations::from_vec_and_domain(vec![beta; domain.size()], domain);
        let f_eval = Evaluations::from_vec_and_domain(domain.fft(&f_x.coeffs), domain);
        let t_x_eval = Evaluations::from_vec_and_domain(domain.fft(&t_x.coeffs), domain);
        let t_gx_eval = Evaluations::from_vec_and_domain(domain.fft(&t_gx.coeffs), domain);
        let Z_gx_eval = Evaluations::from_vec_and_domain(domain.fft(&Z_gx.coeffs), domain);
        let h1_x_eval = Evaluations::from_vec_and_domain(domain.fft(&h1_x.coeffs), domain);
        let h2_x_eval = Evaluations::from_vec_and_domain(domain.fft(&h2_x.coeffs), domain);
        let h1_gx_eval = Evaluations::from_vec_and_domain(domain.fft(&h1_gx.coeffs), domain);
        let h2_gx_eval = Evaluations::from_vec_and_domain(domain.fft(&h2_gx.coeffs), domain);

        let left = &(&(&(&x_minus_g_to_n_plus_1_eval * &Z_eval) * &one_plus_beta_eval) * &(&gamma_eval + &f_eval)) * &(&(&(&gamma_eval * &one_plus_beta_eval) +  &t_x_eval) + &(&beta_eval * &t_gx_eval));
        let right = &(&(&x_minus_g_to_n_plus_1_eval * &Z_gx_eval) * &(&(&(&gamma_eval * &one_plus_beta_eval) + &h1_x_eval) + &(&beta_eval * &h1_gx_eval))) * &(&(&(&gamma_eval * &one_plus_beta_eval) + &h2_x_eval) + &(&beta_eval * &h2_gx_eval));
        
        println!("gamma_eval: {:?}\n", gamma_eval);
        println!("beta_eval:  {:?}\n", beta_eval);
        println!("f_eval:     {:?}\n", f_eval);
        println!("t_x_eval :  {:?}\n", t_x_eval);
        println!("t_gx_eval:  {:?}\n", t_gx_eval);
        println!("Z_eval:     {:?}\n", Z_eval);
        println!("Z_gx_eval:  {:?}\n", Z_gx_eval);
        println!("h1_x_eval:  {:?}\n", h1_x_eval);
        println!("h1_gx_eval: {:?}\n", h1_gx_eval);
        println!("h2_x_eval:  {:?}\n", h2_x_eval);
        println!("h2_gx_eval: {:?}\n", h2_gx_eval);

        println!("{:?}", left);
        println!("{:?}", right);
        
/*
        // b:
        let gamma_poly = Polynomial::from_coefficients_vec([gamma]);
        let one_plus_beta_poly = Polynomial::from_coefficients_vec([Scalar::one + beta]);
        let x_minus_g_to_n_plus_1 = Polynomial::from_coefficients_vec([-g.pow(n+1), Scalar::one()]);

        let b_left = x_minus_g_to_n_plus_1 * Z_x * one_plus_beta_poly
            * (gamma_poly + f_x) * (gamma_poly * one_plus_beta_poly + t_x + beta*)

*/
        assert!(0==1);
    }

    fn random_table_and_queries(n: usize) -> (Vec<Scalar>, Vec<Scalar>) {
        let mut rng = rand::thread_rng();

        // create a table of random scalars
        let mut random_table: Vec<Scalar> = (0..n+1).into_iter().map(|i| Scalar::random(&mut rng)).collect();
        random_table.sort();

        // create a table of queries from the table
        let random_queries: Vec<Scalar> = (0..n).into_iter().map(|i| random_table[rng.gen_range(0, n+1)]).collect();

        (random_table, random_queries)
    }
}