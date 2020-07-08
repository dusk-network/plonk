mod proverkey;
mod verifierkey;

pub use proverkey::ProverKey;
pub use verifierkey::VerifierKey;

// Note: The ECC gadget does not check that the initial point is on the curve for two reasons:
//  - We constrain the accumulator to start from the identity point, which the verifier knows is on the curve
// - We are adding multiples of the generator to the accumulator which the verifier also knows is on the curve and is prime order
// - We do allow arbitrary Scalar multiplication, and possibly XXX: may add constraints to ensure the generator is correct (prime order)
