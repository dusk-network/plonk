use algebra::{curves::bls12_381::Bls12_381, PairingEngine};
use ff_fft::DensePolynomial as Polynomial;
use poly_commit::kzg10::{Commitment, Error, Powers, UniversalParams, VerifierKey, KZG10};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

// modification of https://github.com/scipr-lab/poly-commit/blob/master/src/kzg10/mod.rs

type KZG_Bls12_381 = KZG10<Bls12_381>;

pub fn setup(max_deg: usize) -> UniversalParams<Bls12_381> {
    // TODO - Validate the crypto security of this approach - Need to deterministically generate a
    // srs
    let buf = max_deg.to_le_bytes();
    let mut seed = [0x00u8; 32];

    (&mut seed[0..buf.len()]).copy_from_slice(&buf[..]);
    let mut rng = StdRng::from_seed(seed);

    KZG_Bls12_381::setup(max_deg, false, &mut rng).unwrap()
}

pub fn trim<'a, E: PairingEngine>(
    pp: &UniversalParams<E>,
    mut supported_degree: usize,
) -> Result<(Powers<'a, E>, VerifierKey<E>), Error> {
    if supported_degree == 1 {
        supported_degree += 1;
    }
    let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
    let powers_of_gamma_g = pp.powers_of_gamma_g[..=supported_degree].to_vec();

    let powers = Powers {
        powers_of_g: std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: std::borrow::Cow::Owned(powers_of_gamma_g),
    };
    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };
    Ok((powers, vk))
}

// XXX: This seems to panic on polynomials with zero degree
pub fn commit<E: PairingEngine>(powers: &Powers<E>, p_slice: &[E::Fr]) -> Commitment<E> {
    let p = Polynomial::from_coefficients_slice(p_slice);
    let hiding_bound = None;
    let (comm, _) = KZG10::commit(&powers, &p, hiding_bound, None).unwrap();
    comm
}
