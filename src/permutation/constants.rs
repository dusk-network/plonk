use dusk_bls12_381::Scalar;

/// Constants used in the permutation argument to ensure that the wire subsets are disjoint.
pub(crate) const K1: Scalar = Scalar::from_raw([7, 0, 0, 0]);
pub(crate) const K2: Scalar = Scalar::from_raw([13, 0, 0, 0]);
pub(crate) const K3: Scalar = Scalar::from_raw([17, 0, 0, 0]);

#[cfg(test)]
mod test {
    use crate::fft::EvaluationDomain;
    use crate::permutation::constants::*;
    use rayon::prelude::*;
    #[test]
    fn test_cosets_are_distinct() {
        let n = 2usize.pow(31);
        let h = EvaluationDomain::new(n).unwrap();

        // Supposedly these are the four cosets
        let h_elements = h.elements();
        let k1_H = h.elements().map(|h| h * &K1);
        let k2_H = h.elements().map(|h| h * &K2);
        let k3_H = h.elements().map(|h| h * &K3);

        // Concatenate all cosets together
        let mut all_cosets: Vec<_> = h_elements
            .chain(k1_H)
            .chain(k2_H)
            .chain(k3_H)
            .par_bridge()
            .collect();

        // Sort and remove any duplicates
        all_cosets.sort_by(|a, b| a.cmp(b));
        all_cosets.dedup();

        // If all cosets were distinct then we should not have any elements missing
        assert_eq!(all_cosets.len(), 4 * n);
    }
}
