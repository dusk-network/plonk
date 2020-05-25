use crate::commitment_scheme::kzg10::Commitment;
use crate::proof_system::linearisation_poly::ProofEvaluations;
use dusk_bls12_381::{G1Affine, Scalar};

#[derive(Debug)]
pub struct VerifierKey {
    pub q_m: Commitment,
    pub q_l: Commitment,
    pub q_r: Commitment,
    pub q_o: Commitment,
    pub q_c: Commitment,
    pub q_4: Commitment,
    pub q_arith: Commitment,
}

impl VerifierKey {
    pub(crate) fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<Scalar>,
        points: &mut Vec<G1Affine>,
        evaluations: &ProofEvaluations,
    ) {
        let q_arith_eval = evaluations.q_arith_eval;

        scalars.push(evaluations.a_eval * evaluations.b_eval * q_arith_eval);
        points.push(self.q_m.0);

        scalars.push(evaluations.a_eval * q_arith_eval);
        points.push(self.q_l.0);

        scalars.push(evaluations.b_eval * q_arith_eval);
        points.push(self.q_r.0);

        scalars.push(evaluations.c_eval * q_arith_eval);
        points.push(self.q_o.0);

        scalars.push(evaluations.d_eval * q_arith_eval);
        points.push(self.q_4.0);

        scalars.push(q_arith_eval);
        points.push(self.q_c.0);
    }
}
