use super::{EvaluationDomain, Evaluations};
use bls12_381::Scalar;
use rand::Rng;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use std::ops::{Add, AddAssign, Deref, DerefMut, Div, Mul, Neg, Sub, SubAssign};
// This library will solely implement Dense Polynomials
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Polynomial {
    /// The coefficient of `x^i` is stored at location `i` in `self.coeffs`.
    pub coeffs: Vec<Scalar>,
}

impl Deref for Polynomial {
    type Target = [Scalar];

    fn deref(&self) -> &[Scalar] {
        &self.coeffs
    }
}

impl DerefMut for Polynomial {
    fn deref_mut(&mut self) -> &mut [Scalar] {
        &mut self.coeffs
    }
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
            sum = sum + summand
        }
        sum
    }

    /// Outputs a polynomial of degree `d` where each coefficient is sampled
    /// uniformly at random from the field `F`.
    pub fn rand<R: Rng>(d: usize, mut rng: &mut R) -> Self {
        let mut random_coeffs = Vec::with_capacity(d + 1);
        for _ in 0..=d {
            random_coeffs.push(random_scalar(&mut rng));
        }
        Self::from_coefficients_vec(random_coeffs)
    }
}

// bls_12-381 library does not provide a `random` method for Scalar
// We wil use this helper function to compensate
pub(crate) fn random_scalar<R: Rng>(rng: &mut R) -> Scalar {
    Scalar::from_raw([
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
        rng.next_u64(),
    ])
}

///////////
impl<'a, 'b> Add<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    fn add(self, other: &'a Polynomial) -> Polynomial {
        let mut result = if self.is_zero() {
            other.clone()
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            for (a, b) in result.coeffs.iter_mut().zip(&other.coeffs) {
                *a += b
            }
            result
        } else {
            let mut result = other.clone();
            for (a, b) in result.coeffs.iter_mut().zip(&self.coeffs) {
                *a += b
            }
            result
        };
        result.truncate_leading_zeros();
        result
    }
}

impl<'a, 'b> AddAssign<&'a Polynomial> for Polynomial {
    fn add_assign(&mut self, other: &'a Polynomial) {
        if self.is_zero() {
            self.coeffs.truncate(0);
            self.coeffs.extend_from_slice(&other.coeffs);
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a += b
            }
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), Scalar::zero());
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a += b
            }
            self.truncate_leading_zeros();
        }
    }
}

impl<'a, 'b> AddAssign<(Scalar, &'a Polynomial)> for Polynomial {
    fn add_assign(&mut self, (f, other): (Scalar, &'a Polynomial)) {
        if self.is_zero() {
            self.coeffs.truncate(0);
            self.coeffs.extend_from_slice(&other.coeffs);
            self.coeffs.iter_mut().for_each(|c| *c *= &f);
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a += &(f * b);
            }
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), Scalar::zero());
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a += &(f * b);
            }
            self.truncate_leading_zeros();
        }
    }
}

impl Neg for Polynomial {
    type Output = Polynomial;

    #[inline]
    fn neg(mut self) -> Polynomial {
        for coeff in &mut self.coeffs {
            *coeff = -*coeff;
        }
        self
    }
}

impl<'a, 'b> Sub<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn sub(self, other: &'a Polynomial) -> Polynomial {
        let mut result = if self.is_zero() {
            let mut result = other.clone();
            for coeff in &mut result.coeffs {
                *coeff = -(*coeff);
            }
            result
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            for (a, b) in result.coeffs.iter_mut().zip(&other.coeffs) {
                *a -= b
            }
            result
        } else {
            let mut result = self.clone();
            result.coeffs.resize(other.coeffs.len(), Scalar::zero());
            for (a, b) in result.coeffs.iter_mut().zip(&other.coeffs) {
                *a -= b;
            }
            result
        };
        result.truncate_leading_zeros();
        result
    }
}

impl<'a, 'b> SubAssign<&'a Polynomial> for Polynomial {
    #[inline]
    fn sub_assign(&mut self, other: &'a Polynomial) {
        if self.is_zero() {
            self.coeffs.resize(other.coeffs.len(), Scalar::zero());
            for (i, coeff) in other.coeffs.iter().enumerate() {
                self.coeffs[i] -= coeff;
            }
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a -= b
            }
        } else {
            // Add the necessary number of zero coefficients.
            self.coeffs.resize(other.coeffs.len(), Scalar::zero());
            for (a, b) in self.coeffs.iter_mut().zip(&other.coeffs) {
                *a -= b
            }
            // If the leading coefficient ends up being zero, pop it off.
            self.truncate_leading_zeros();
        }
    }
}

impl<'a, 'b> Div<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn div(self, other: &'a Polynomial) -> Polynomial {
        if self.is_zero() || other.is_zero() {
            Polynomial::zero()
        } else {
            self.divide_with_q_and_r(other).expect("division failed").0
        }
    }
}
// XXX: We should refactor this polynomial division impl
impl Polynomial {
    #[inline]
    fn leading_coefficient(&self) -> Option<&Scalar> {
        self.last()
    }

    #[inline]
    fn iter_with_index(&self) -> Vec<(usize, Scalar)> {
        self.iter().cloned().enumerate().collect()
    }
    /// Divide self by another (sparse or dense) polynomial, and returns the
    /// quotient and remainder.
    pub(crate) fn divide_with_q_and_r(&self, divisor: &Self) -> Option<(Polynomial, Polynomial)> {
        if self.is_zero() {
            Some((Polynomial::zero(), Polynomial::zero()))
        } else if divisor.is_zero() {
            panic!("Dividing by zero polynomial")
        } else if self.degree() < divisor.degree() {
            Some((Polynomial::zero(), self.clone().into()))
        } else {
            // Now we know that self.degree() >= divisor.degree();
            let mut quotient = vec![Scalar::zero(); self.degree() - divisor.degree() + 1];
            let mut remainder: Polynomial = self.clone().into();
            // Can unwrap here because we know self is not zero.
            let divisor_leading_inv = divisor.leading_coefficient().unwrap().invert().unwrap();
            while !remainder.is_zero() && remainder.degree() >= divisor.degree() {
                let cur_q_coeff = *remainder.coeffs.last().unwrap() * &divisor_leading_inv;
                let cur_q_degree = remainder.degree() - divisor.degree();
                quotient[cur_q_degree] = cur_q_coeff;

                for (i, div_coeff) in divisor.iter_with_index() {
                    remainder[cur_q_degree + i] -= &(cur_q_coeff * &div_coeff);
                }
                while let Some(true) = remainder.coeffs.last().map(|c| (c == &Scalar::zero())) {
                    remainder.coeffs.pop();
                }
            }
            Some((Polynomial::from_coefficients_vec(quotient), remainder))
        }
    }
}

/// Performs O(nlogn) multiplication of polynomials if F is smooth.
impl<'a, 'b> Mul<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn mul(self, other: &'a Polynomial) -> Polynomial {
        if self.is_zero() || other.is_zero() {
            Polynomial::zero()
        } else {
            let domain = EvaluationDomain::new(self.coeffs.len() + other.coeffs.len())
                .expect("field is not smooth enough to construct domain");
            let mut self_evals = Evaluations::from_vec_and_domain(domain.fft(&self.coeffs), domain);
            let other_evals = Evaluations::from_vec_and_domain(domain.fft(&other.coeffs), domain);
            self_evals *= &other_evals;
            self_evals.interpolate()
        }
    }
}
/// Performs O(nlogn) multiplication of polynomials if F is smooth.
impl<'a, 'b> Mul<&'a Scalar> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn mul(self, constant: &'a Scalar) -> Polynomial {
        if self.is_zero() || (constant == &Scalar::zero()) {
            return Polynomial::zero();
        }
        let scaled_coeffs: Vec<_> = self.coeffs.iter().map(|coeff| coeff * constant).collect();
        Polynomial::from_coefficients_vec(scaled_coeffs)
    }
}

#[test]
fn test_div() {
    // X^2 + 4x + 4
    let quadratic =
        Polynomial::from_coefficients_vec(vec![Scalar::from(4), Scalar::from(4), Scalar::one()]);
    // X+2
    let factor = Polynomial::from_coefficients_vec(vec![Scalar::from(2), Scalar::one()]);

    let quotient = &quadratic / &factor;
    dbg!(quotient.degree(), quadratic.degree());
    assert_eq!(quotient, factor);
}
