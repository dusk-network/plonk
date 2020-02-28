use new_bls12_381::Scalar;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
// This library will solely implement Dense Polynomials
pub struct Polynomial {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    pub coeffs: Vec<Scalar>,
}

impl Polynomial {
    /// Returns the zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: Vec::new() }
    }

    /// Checks if the given polynomial is zero.
    pub fn is_zero(&self) -> bool {
        self.coeffs.is_empty() || self.coeffs.iter().all(|coeff| coeff == &Scalar::zero())
    }

    /// Constructs a new polynomial from a list of coefficients.
    pub fn from_coefficients_slice(coeffs: &[Scalar]) -> Self {
        Self::from_coefficients_vec(coeffs.to_vec())
    }

    /// Constructs a new polynomial from a list of coefficients.
    pub fn from_coefficients_vec(coeffs: Vec<Scalar>) -> Self {
        let mut result = Self { coeffs };
        // While there are zeros at the end of the coefficient vector, pop them off.
        result.truncate_leading_zeros();
        // Check that either the coefficients vec is empty or that the last coeff is
        // non-zero.
        assert!(result
            .coeffs
            .last()
            .map_or(true, |coeff| !(coeff == &Scalar::zero())));

        result
    }

    /// Returns the degree of the polynomial.
    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            assert!(self
                .coeffs
                .last()
                .map_or(false, |coeff| !(coeff == &Scalar::zero())));
            self.coeffs.len() - 1
        }
    }

    fn truncate_leading_zeros(&mut self) {
        while self.coeffs.last().map_or(false, |c| c == &Scalar::zero()) {
            self.coeffs.pop();
        }
    }
    /// Evaluates `self` at the given `point` in the field.
    pub fn evaluate(&self, point: Scalar) -> Scalar {
        if self.is_zero() {
            return Scalar::zero();
        }
        let mut powers_of_point = vec![Scalar::one()];
        let mut cur = point;
        for _ in 0..self.degree() {
            powers_of_point.push(cur);
            cur *= &point;
        }
        assert_eq!(powers_of_point.len(), self.coeffs.len());
        let partial_sum: Vec<_> = powers_of_point
            .into_par_iter()
            .zip(&self.coeffs)
            .map(|(power, coeff)| power * coeff)
            .collect();

        let mut sum = Scalar::zero();
        for summand in partial_sum {
            sum += summand
        }
        sum
    }
}
