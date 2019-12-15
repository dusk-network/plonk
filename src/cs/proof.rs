use algebra::curves::PairingEngine;
use poly_commit::kzg10::Commitment;

pub struct Proof<E: PairingEngine> {
    // Commitment to the witness polynomial for the left wires
    a_comm: Commitment<E>,
    // Commitment to the witness polynomial for the right wires
    b_comm: Commitment<E>,
    // Commitment to the witness polynomial for the output wires
    c_comm: Commitment<E>,

    // Commitment to the permutation polynomial
    z_comm: Commitment<E>,

    // Commitment to the quotient polynomial
    t_lo_comm: Commitment<E>,
    t_mid_comm: Commitment<E>,
    t_hi_comm: Commitment<E>,

    // Commitment to the opening polynomial
    w_z_comm: Commitment<E>,
    // Commitment to the shifted opening polynomial
    w_zw_comm: Commitment<E>,

    // Evaluation of the witness polynomial for the left wires at `z`
    a_eval: E::Fr,
    // Evaluation of the witness polynomial for the right wires at `z`
    b_eval: E::Fr,
    // Evaluation of the witness polynomial for the output wires at `z`
    c_eval: E::Fr,

    // Evaluation of the left sigma polynomial at `z`
    left_sigma_eval: E::Fr,
    // Evaluation of the right sigma polynomial at `z`
    right_sigma_eval: E::Fr,

    // Evaluation of the linearisation sigma polynomial at `z`
    lin_poly_eval: E::Fr,

    // (Shifted) Evaluation of the permutation polynomial at `z * root of unity`
    z_eval: E::Fr,
    // XXX: Need to confirm that for custom gates we do need more commitments for custom selector polynomial, as the selector polynomial is a part of the circit description
    // Furthermore, we may not need any extra commitments as the checks are baked into the quotient polynomial and the setup elements can be put into the witness polynomials
}

impl<E: PairingEngine> Proof<E> {
    pub fn empty() -> Proof<E> {
        use algebra::fields::Field;
        use poly_commit::data_structures::PCCommitment;
        Proof {
            a_comm: Commitment::empty(),
            b_comm: Commitment::empty(),
            c_comm: Commitment::empty(),

            z_comm: Commitment::empty(),

            t_lo_comm: Commitment::empty(),
            t_mid_comm: Commitment::empty(),
            t_hi_comm: Commitment::empty(),

            w_z_comm: Commitment::empty(),
            w_zw_comm: Commitment::empty(),

            a_eval: E::Fr::zero(),
            b_eval: E::Fr::zero(),
            c_eval: E::Fr::zero(),

            left_sigma_eval: E::Fr::zero(),
            right_sigma_eval: E::Fr::zero(),

            lin_poly_eval: E::Fr::zero(),

            z_eval: E::Fr::zero(),
        }
    }
}
