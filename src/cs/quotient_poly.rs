use algebra::{curves::PairingEngine, fields::Field};
use ff_fft::{DensePolynomial as Polynomial, EvaluationDomain};
use std::marker::PhantomData;

pub struct QuotientToolkit<E: PairingEngine> {
    _engine: PhantomData<E>,
}
impl<E: PairingEngine> QuotientToolkit<E> {
    pub fn new() -> Self {
        QuotientToolkit {
            _engine: PhantomData,
        }
    }

    /// Computes the Lagrange polynomial evaluation `L1(z)`. 
    pub fn compute_lagrange_poly_evaluation(&self, n: u8) -> Polynomial<E::Fr> {
        // One as a polynomial of degree 0. 
        let one_poly = Polynomial::from_coefficients_slice(&[E::Fr::from(1)]);
        // Build z_nth vector to get the poly directly in coef form.
        let mut z_nth = Vec::new();
        for _ in 0..n {
            z_nth.push(E::Fr::zero());
        };
        // Add 1 on the n'th term of the vec. 
        z_nth.push(E::Fr::from(1));
        // Build the poly. 
        let z_nth_poly = Polynomial::from_coefficients_vec(z_nth);
        // `n` as polynomial of degree 0. 
        let n_poly = Polynomial::from_coefficients_slice(&[E::Fr::from(n as u8)]);
        let z_poly = Polynomial::from_coefficients_slice(&[E::Fr::zero(), E::Fr::from(1)]);

        &(&z_nth_poly - &one_poly) / &(&n_poly * &(&z_poly - &one_poly))
    }

    // Moves the polynomial on the complex plane in respect to the 
    // first root of unity.
    pub fn transpolate_poly_to_unity_root(&self, n: usize, poly: &Polynomial<E::Fr>) -> Polynomial<E::Fr> {
        let domain_4n = EvaluationDomain::new(4*n).unwrap();
        let mut poly_coef = domain_4n.fft(poly);
        poly_coef.push(poly_coef[0]);
        poly_coef.push(poly_coef[1]);
        poly_coef.push(poly_coef[2]);
        poly_coef.push(poly_coef[3]);
        let mut coefs_rotated: Vec<E::Fr> = Vec::with_capacity(poly_coef.len());
        coefs_rotated.clone_from_slice(&poly_coef[4..]);
        let final_poly = Polynomial::from_coefficients_vec(domain_4n.ifft(&coefs_rotated));
        final_poly
    }

    // Split `t(X)` poly into degree-n polynomials.
    pub fn split_tx_poly(&self, n: usize, t_x: Polynomial<E::Fr>) -> [Polynomial<E::Fr>;3] {
        let zero = E::Fr::zero();

        let t_lo: Vec<E::Fr> = t_x.into_iter()
        .enumerate()
        .filter(|(i, _)| i <= &n)
        .map(|(_, x)| *x)
        .collect();

        let t_mid: Vec<E::Fr> = t_x.into_iter()
        .enumerate()
        .filter(|(i, _)| i <= &(2*n))
        .map(|(i, mut x)| {
            if i == n {
                x = &zero;
            }
            *x
        })
        .collect();

        let t_hi: Vec<E::Fr> = t_x.into_iter()
        .enumerate()
        .filter(|(i, _)| i <= &(3*n))
        .map(|(i, mut x)| {
            if i == n || i == 2*n {
                x = &zero;
            }
            *x
        })
        .collect();
        
        [
        Polynomial::from_coefficients_vec(t_lo), 
        Polynomial::from_coefficients_vec(t_mid), 
        Polynomial::from_coefficients_vec(t_hi),
        ]
    }
}