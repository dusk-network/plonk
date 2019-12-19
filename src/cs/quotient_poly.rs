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

    // Gets a set of polynomials, passes them to coeficient form
    // with EvalDomain = 4*n. Then multiplies them by `z(Xw)` and
    // returns the ifft of the mul over the domain `4n` again.
    pub fn mul_and_transp_in_4n(&self, n: usize, t2s_polys: &[Polynomial<E::Fr>; 3], z_poly: &Polynomial<E::Fr>) -> Polynomial<E::Fr> {
        let ev_dom_4n = EvaluationDomain::new(4*n).unwrap();
        let polys_4n: Vec<Polynomial<E::Fr>> = t2s_polys.into_iter()
        .map(|p| {
            let pol = {Polynomial::from_coefficients_slice(&ev_dom_4n.fft(p))};
            pol    
        })
        .collect();

        let z_eval_coef = self.transpolate_poly_to_unity_root(n, &z_poly);

        let total_poly: Polynomial<E::Fr> = {
            let mut tot: Polynomial<E::Fr> = Polynomial::zero();
            for poly in polys_4n {
                tot = &tot * &poly; 
            }   
            tot = &tot * &z_eval_coef;
            tot
        };
        
        Polynomial::from_coefficients_slice(&ev_dom_4n.ifft(&total_poly)) 
    }

    // Moves the polynomial on the complex plane in respect to the 
    // first root of unity and returns the poly in coeficient form.
    pub fn transpolate_poly_to_unity_root(&self, n: usize, poly: &Polynomial<E::Fr>) -> Polynomial<E::Fr> {
        let domain_4n = EvaluationDomain::new(4*n).unwrap();
        let mut poly_coef = domain_4n.fft(poly);
        poly_coef.push(poly_coef[0]);
        poly_coef.push(poly_coef[1]);
        poly_coef.push(poly_coef[2]);
        poly_coef.push(poly_coef[3]);
        let mut coefs_rotated: Vec<E::Fr> = Vec::with_capacity(poly_coef.len());
        coefs_rotated.clone_from_slice(&poly_coef[4..]);
        Polynomial::from_coefficients_vec(coefs_rotated)
    }

    // Split `t(X)` poly into degree-n polynomials.
    pub fn split_tx_poly(&self,n: usize, t_x: Polynomial<E::Fr>) -> [Polynomial<E::Fr>;3] {
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
#[cfg(test)]
mod test {
    use super::*;
    use algebra::fields::bls12_381::Fr;
    use algebra::curves::bls12_381::Bls12_381 as E;

    #[test]
    fn test_split_poly() {
        let n = 10;
        
        // Compute random point
        use algebra::UniformRand;
        let rand_point = Fr::rand(&mut rand::thread_rng());
        let rand_point_n = rand_point.pow(&[n as u64]);
        let rand_point_2n = rand_point.pow(&[2 * n as u64]);

        // Generate a random quotient polynomial
        let t_x = Polynomial::rand(3*n, &mut rand::thread_rng());
        let t_x_eval = t_x.evaluate(rand_point);

        // Split t(x) into 3 n-degree polynomials
        let toolkit: QuotientToolkit<E> = QuotientToolkit::new();
        let t_components = toolkit.split_tx_poly(n,t_x);

        // Eval n-degree polynomials
        let t_lo_eval = t_components[0].evaluate(rand_point);
        
        let mut t_mid_eval = t_components[1].evaluate(rand_point);
        t_mid_eval = t_mid_eval * &rand_point_n;

        let mut t_hi_eval = t_components[2].evaluate(rand_point);
        t_hi_eval = t_hi_eval * &rand_point_2n;

        let mut t_components_eval = t_lo_eval + &t_mid_eval;
        t_components_eval += &t_hi_eval;

        assert_eq!(t_x_eval, t_components_eval);
    }
}