use bls12_381::Scalar;
use rayon::prelude::*;
pub struct Poly_utils {}

impl Poly_utils {
    pub fn new() -> Self {
        Poly_utils {}
    }

    pub fn add_poly_vectors(&self, poly_a: &[Scalar], poly_b: &[Scalar]) -> Vec<Scalar> {
        if poly_a.len() == 0 {
            return poly_b.to_vec();
        }
        if poly_b.len() == 0 {
            return poly_a.to_vec();
        }

        let max_len = std::cmp::max(poly_a.len(), poly_b.len());
        let min_len = std::cmp::min(poly_a.len(), poly_b.len());
        let mut data = Vec::with_capacity(max_len);
        let (mut poly_a_iter, mut poly_b_iter) = (poly_a.iter(), poly_b.iter());

        let partial_addition = poly_a_iter
            .by_ref()
            .zip(poly_b_iter.by_ref())
            .map(|(&a, &b)| a + &b)
            .take(min_len);

        data.extend(partial_addition);
        data.extend(poly_a_iter);
        data.extend(poly_b_iter);

        assert_eq!(data.len(), std::cmp::max(poly_a.len(), poly_b.len()));

        data
    }

    // Evaluates multiple polynomials at the same point
    pub fn multi_point_eval(&self, polynomials: Vec<&[Scalar]>, point: &Scalar) -> Vec<Scalar> {
        // Find the highest degree polynomial
        let mut max_coefficients = 0;
        for poly in polynomials.iter() {
            let num_coefficients = poly.len();
            if num_coefficients > max_coefficients {
                max_coefficients = num_coefficients
            }
        }
        assert_ne!(max_coefficients, 0);

        // Compute powers of points
        let powers = self.powers_of(point, max_coefficients);

        // Compute evaluation of each polynomial at `point`
        let evaluations: Vec<Scalar> = polynomials
            .par_iter()
            .map(|poly| {
                if poly.len() == 0 {
                    return Scalar::zero();
                }

                let mut p_evals: Vec<_> = poly
                    .iter()
                    .zip(powers.iter())
                    .map(|(c, p)| *p * c)
                    .collect();
                let mut sum = Scalar::zero();
                for eval in p_evals.into_iter() {
                    sum += &eval;
                }
                sum
            })
            .collect();

        evaluations
    }

    pub fn single_point_eval(&self, polynomial: &[Scalar], point: &Scalar) -> Scalar {
        if polynomial.len() == 0 {
            return Scalar::zero();
        }

        // Compute powers of points
        let mut powers = self.powers_of(point, polynomial.len());

        let p_evals: Vec<_> = polynomial
            .par_iter()
            .zip(powers.into_par_iter())
            .map(|(c, p)| p * c)
            .collect();
        let mut sum = Scalar::zero();
        for eval in p_evals.into_iter() {
            sum += &eval;
        }
        sum
    }
    // Multiplies a polynomial by a scalar
    pub fn mul_scalar_poly(&self, scalar: Scalar, poly: &[Scalar]) -> Vec<Scalar> {
        poly.par_iter().map(|coeff| scalar * coeff).collect()
    }
    // Computes 1,v, v^2, v^3,..v^max_degree
    pub fn powers_of(&self, scalar: &Scalar, max_degree: usize) -> Vec<Scalar> {
        let mut powers = Vec::with_capacity(max_degree + 1);
        powers.push(Scalar::one());
        for i in 1..=max_degree {
            powers.push(powers[i - 1] * scalar);
        }
        powers
    }
}
