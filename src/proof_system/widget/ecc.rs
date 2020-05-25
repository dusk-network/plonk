// This file will contain the logic required
// to perform ECC operations in a PLONK
// circuit.

// For the scalar base operations we need to
// build a look up table, where we can find
// the values of particular indexes in 
#![allow(clippy::too_many_arguments)]
use super::PreProcessedPolynomial;
use crate::commitment_scheme::kzg10::Commitment;
use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearisation_poly::ProofEvaluations;
use jubjub::{AffinePoint, GENERATOR, Fq, Fr};

#[cfg(feature = "serde")]
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Eq, PartialEq)]
pub struct ECCWidget {
    pub q_ecc: PreProcessedPolynomial,
    pub q_c: PreProcessedPolynomial,
}

#[cfg(feature = "serde")]
impl Serialize for ECCWidget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ecc_widget = serializer.serialize_struct("struct ECCWidget", 2)?;
        ecc_widget.serialize_field("q_c", &self.q_c)?;
        ecc_widget.serialize_field("q_eee", &self.q_ecc)?;
        ecc_widget.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for LogicWidget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Qc,
            Qecc,
        };

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        formatter.write_str("struct ECCWidget")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "q_c" => Ok(Field::Qc),
                            "q_ecc" => Ok(Field::Qecc),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ECCWidgetVisitor;

        impl<'de> Visitor<'de> for ECCWidgetVisitor {
            type Value = ECCWidget;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct ECCWidget")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<LogicWidget, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let q_c = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let q_ecc = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(LogicWidget { q_c, q_ecc })
            }
        }

        const FIELDS: &[&str] = &["q_c", "q_ecc"];
        deserializer.deserialize_struct("ECCWidget", FIELDS, ECCWidgetVisitor)
    }
}

impl ECCWidget {
    pub(crate) fn new(
        q_c: (Polynomial, Commitment, Option<Evaluations>),
        q_ecc: (Polynomial, Commitment, Option<Evaluations>),
    ) -> ECCWidget {
        ECCWidget {
            q_c: PreProcessedPolynomial::new(q_ecc),
            q_ecc: PreProcessedPolynomial::new(q_ecc),
        }
    }
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        ecc_consistency_challenge: &Fr,
        w_l_i: &Fr,
        w_l_i_next: &Fr,
        w_r_i: &Fr,
        w_r_i_next: &Fr,
        w_o_i: &Fr,
        w_o_i_next: &Fr,
        w_4_i: &Fr,
        w_4_i_next: &Fr,
        q_5_i: &Fr,
        q_m_i: &Fr,
        q_4_i: &Fr
        q_c_i: &Fr,
        q_1_i: &Fr,
        q_2_i: &Fr,
    ) -> Fr {
    
        let q_ecc_i = &self.q_ecc.evaluations.as_ref().unwrap()[index];
        let q_c_i = &self.q_o.evaluations.as_ref().unwrap()[index];
        
        let four = Scalar::from(4);
        let nine = Scalar::from(9);
        let one = Scalar::one();
    
        let kappa = ecc_consistency_challenge.square();
        let kappa_2 = kappa.square();
        let kappa_3 = kappa_2 * kappa;
        let kappa_4 = kappa_3 * kappa;
        let kappa_5 = kappa_4 * kappa;
        let kappa_6 = kappa_5 * kappa;
        let kappa_7 = kappa_6 * kappa;
        let kappa_8 = kappa_7 * kappa;
    
        /// Compute the accumulator which tracks the current 
        /// rounds scalar multiplier, which is depedent on the 
        /// input bit
        let acc_input = four * w_4_i;
        let accum = w_4_i_next - acc_input;
    
        let accum_sqr = accum.square();
        
        /// To compute the y-alpha, which is the y-coordinate that corresponds to the x which is added 
        /// in each round then we use the formula below. This y-alpha is the y-coordianate that corresponds 
        /// to the y of one of the two points in the look up table, or the y in their inverses. 
        let a = w_o_i_next * q_o_i;
        let b = a + q_ecc_i;
        let y_alpha = b * accum;
        
    
        /// Check that the accumulator consistency at the identity element
        /// (accum - 1)(accum - 3)(accum + 1)(accum + 3) = 0 
        let a = accum_sqr - 9; 
        let b = accum_sqr - 1;
        let scalar_accum = a * b;
        let c1 = scalar_accum * kappa;
    
    
        /// To compute x-alpha, which is the x-coordinate that we're adding in at each round. We need to
        /// explicit formualae with selector polynomials based on the values given in the lookup table.
        let a = accum_sqr * q_1_i;
        let b = a + q_2_i;
        let x_alpha_identity = b - w_o_i_next;
        let w1 = x_alpha_identity * kappa_2;
        
        /// Consistency check of the x_accumulator
        let a = (w_l_i_next + w_l_i + w_o_i_next);
        let b = (w_o_i_next - w_l_i);
        let c = b.square();
        let d = y_alpha - w_r_i;
        let e = d.square();
        let x_accumulator = (a + c) - e;
        let a1 = x_accumulator * kappa_3;
    
        /// Consistency check of the y_accumulator;
        let a = w_r_i_next - w_r_i;
        let b = w_o_i_next - w_l_i;
        let c = y_alpha - w_r_i;
        let d = w_l_i - w_l_i_next;
        let y_accumulator = (a + b) * (c + d);
        let b1 = y_accumulator * kappa_4;
    
        /// Scalar accumulator consistency check;
        let a = w_4_i - 1 - w_o_i;
        let accum_init = a.square();
        let c0 = accum_init * kappa_5;
        
        /// x_initial value consistency check;
        let a = w_4_i - 1;
        let b = (q_4_i - w_l_i) * w_o_i; 
        let c = a * q_5_i;
        let x_inital = b - c;
        let a0 = x_inital * kappa_6;
    
        /// y_initial value consistency check;
        let a = w_4_i - 1;
        let b = (q_m_i - w_r_i) * w_o_i;
        let c = a * q_c_i;
        let y_initial = b - c;
        let b0 = y_initial * kappa_7;
    
        let n = delta_ecc(&c0, &a0, &b0, &c1, &w1, &a1, &b1, &q_c) * kappa_8;

        q_ecc_i * &n
    }
    
    pub(crate) fn compute_linearisation(
        &self,
        ecc_consistency_challenge: &Fr,
        a_eval: &Fr,
        a_next_eval: &Fr,
        b_eval: &Fr,
        b_next_eval: &Fr,
        c_eval: &Fr,
        c_next_eval: &Fr,
        d_eval: &Fr,
        d_next_eval: &Fr,
        q_c_eval: &Fr,
        q_o_eval: &Fr,
        q_1_eval: &Fr,
        q_2_eval: &Fr,
        q_m_eval: &Fr,
        q_4_eval: &Fr,
        q_5_eval: &Fr,
    ) -> Polynomial{


        let q_ecc_poly = &self.q_ecc.polynomial;
        let q_c_eval = &self.q_o.polynomial;

        let four = Scalar::from(4);
        let nine = Scalar::from(9);
        let one = Scalar::one();
    
            
        
        let kappa = ecc_consistency_challenge.square();
        let kappa_2 = kappa.square();
        let kappa_3 = kappa_2 * kappa;
        let kappa_4 = kappa_3 * kappa;
        let kappa_5 = kappa_4 * kappa;
        let kappa_6 = kappa_5 * kappa;
        let kappa_7 = kappa_6 * kappa;
        let kappa_8 = kappa_7 * kappa;
        
        /// Compute the accumulator which tracks the current 
        /// rounds scalar multiplier, which is depedent on the 
        /// input bit
        let acc_input = four *a_eval;
        let accum = a_next_eval - acc_input;
        
        let accum_sqr = accum.square();
            
        /// To compute the y-alpha, which is the y-coordinate that corresponds to the x which is added 
        /// in each round then we use the formula below. This y-alpha is the y-coordianate that corresponds 
        /// to the y of one of the two points in the look up table, or the y in their inverses. 
        let a = c_next_eval * q_o_eval;
        let b = a + q_ecc_eval;
        let y_alpha = b * accum;
        
        
        /// Check that the accumulator consistency at the identity element
        /// (accum - 1)(accum - 3)(accum + 1)(accum + 3) = 0 
        let a = accum_sqr - 9; 
        let b = accum_sqr - 1;
        let scalar_accum_eval = a * b;
        let c1 = scalar_accum_eval * kappa;
        
     
        /// To compute x-alpha, which is the x-coordinate that we're adding in at each round. We need to
        /// explicit formualae with selector polynomials based on the values given in the lookup table.
        let a = accum_sqr * q_1_i_eval;
        let b = a + q_2_eval;
        let x_alpha_identity_eval = b - c_next_eval;
        let w1 = x_alpha_identity_eval * kappa_2;
        
        /// Consistency check of the x_accumulator
        let a = (a_next_eval + a_eval + c_next_eval);
        let b = (c_next_eval - a_eval);
        let c = b.square();
        let d = y_alpha - b_eval;
        let e = d.square();
        let x_accumulator_eval = (a + c) - e;
        let a1 = x_accumulator_eval * kappa_3;
        
        /// Consistency check of the y_accumulator;
        let a = b_next_eval - b_eval;
        let b = c_next_eval - a_eval;
        let c = y_alpha - b_eval;
        let d = a_eval - a_next_eval;
        let y_accumulator_eval = (a + b) * (c + d);
        let b1 = y_accumulator_eval * kappa_4;
        
        /// Scalar accumulator consistency check;
        let a = d_eval - 1 - c_eval;
        let accum_init_eval = a.square();
        let c0 = accum_init_eval * kappa_5;
            
        /// x_initial value consistency check;
        let a = d_eval - 1;
        let b = (q_4_eval - a_eval) * c_eval; 
        let c = a * q_5_eval;
        let x_inital_eval = b - c;
        let a0 = x_inital_eval_eval * kappa_6;
        
        /// y_initial value consistency check;
        let a = d_eval - 1;
        let b = (q_m_eval - b_eval) * c_eval;
        let c = a * q_c_eval;
        let y_initial_eval = b - c;
        let b0 = y_initial_eval * kappa_7;
        
        let n = delta_ecc(&c0, &a0, &b0, &c1, &w1, &a1, &b1, &q_c) * kappa_8;

        q_ecc_poly * &n
    }

    /// Finish this.
    pub(crate) fn compute_linearisation_commitment()
        &self,
        ecc_separation_challenge: &Scalar,
        scalars: &mut Vec<Fr>,
        points: &mut Vec<AffinePoint>,
        evaluations: &ProofEvaluations,



        
        

    
    

}



/// The polynomial identity to be evaluated, will check that the
/// initialiser has been done correctly and check that the accumulating 
/// values are correct. 
/// 
/// The identity checks that q_ecc * A = 0 
/// A = B + C
/// B = q_c * (c + let a + b)
/// C = (c1 + w1 + a1 + b1)
fn delta_ecc(c0: &Fr, a0: &Fr, b0: &Fr, c1: &Fr, w1: &Fr, a1: &Fr, b1: &Fr, q_c: &Fr) -> {
    
    let B = q_c * (c + a + b);
    let C = (c_1 + w_1 + a_1 + b_1);
    B + C

}