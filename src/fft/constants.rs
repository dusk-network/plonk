use bls12_381::Scalar;

// Constants for BLS
// XXX: These are defined in scalar.rs, but do not seem to be reachable
pub const TWO_ADICITY: u32 = 32;
pub const GENERATOR: Scalar = Scalar::from_raw([7, 0, 0, 0]);
pub const ROOT_OF_UNITY: Scalar = Scalar::from_raw([
    0x3829971F439F0D2B,
    0xB63683508C2280B9,
    0xD09B681922C813B4,
    0x16A2A19EDFE81F20,
]);
