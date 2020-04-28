//! proving system

pub(crate) mod linearisation_poly;
pub(crate) mod preprocessed_circuit;
pub(crate) mod proof;
pub(crate) mod proof_system_errors;
pub(crate) mod quotient_poly;
pub(crate) mod widget;

pub use preprocessed_circuit::PreProcessedCircuit;
pub use proof::Proof;
