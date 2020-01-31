use algebra::curves::PairingEngine;
use algebra::fields::Field;
use std::marker::PhantomData;

pub struct Poly_utils<E: PairingEngine> {
    _engine: PhantomData<E>,
}

impl<E: PairingEngine> Poly_utils<E> {
    pub fn new() -> Self {
        Poly_utils {
            _engine: PhantomData,
        }
    }

    pub fn add_poly_vectors(&self, poly_a: &[E::Fr], poly_b: &[E::Fr]) -> Vec<E::Fr> {
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
    // Computes 1,v, v^2, v^3,..v^max_degree
    pub fn powers_of(&self, scalar: &E::Fr, max_degree: usize) -> Vec<E::Fr> {
        let mut powers = Vec::with_capacity(max_degree + 1);
        powers.push(E::Fr::one());
        for i in 1..=max_degree {
            powers.push(powers[i - 1] * scalar);
        }
        powers
    }
}
