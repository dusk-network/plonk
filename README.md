# PLONK [![Build Status](https://travis-ci.com/dusk-network/plonk.svg?branch=master)](https://travis-ci.com/dusk-network/plonk) [![codecov](https://codecov.io/gh/dusk-network/plonk/branch/master/graph/badge.svg)](https://codecov.io/gh/dusk-network/plonk) ![GitHub issues](https://img.shields.io/github/issues-raw/dusk-network/plonk?style=plastic) ![GitHub](https://img.shields.io/github/license/dusk-network/plonk?color=%230E55EF) 



*This is a pure Rust implementation of the PLONK proving system over BLS12-381*

_This code is highly experimental, use at your own risk_.

This library contains a modularised implementation of KZG10 as the default polynomial commitment scheme.

## Example

The following example shows how to setup the SRS and verify whether a value is a boolean
```rust

// Common View - This is information that the prover and verifier will share
// This step is usually performed with a `ceremony` or MPC 
let public_parameters = SRS::setup(999, &mut rand::thread_rng());
  
// Provers View
let (proof, public_inputs) = {
    let mut composer: StandardComposer = add_dummy_composer(7);
        
    // Add Statement you want to prove
    let var_one = composer.add_input(Scalar::from(1));
    let var_four = composer.add_input(Scalar::from(4));
    composer.bool_gate(var_one);
    composer.bool_gate(var_four); // Verification will fail due to this being four

    // Trim the SRS to the size of the circuit
    // The main reason this may fail, is if the circuit size is larger than max_degree poly you can commit to.
    let (ck, _) = public_parameters.trim(composer.circuit_size().next_power_of_two()).unwrap();
    
    // Create a new Evaluation Domain
    let domain = EvaluationDomain::new(composer.circuit_size()).unwrap();
    
    // Initialise Transcript
    let mut transcript = Transcript::new(b"");
    
    // Preprocess circuit
    let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);
            
    // Return Proof along with any public inputs
    // In a real program, the Prover and verifier will know the public inputs
    (
        composer.prove(&ck, &preprocessed_circuit, &mut transcript),
        composer.public_inputs,
    );

}; 


// Verifiers View
//
let ok = {
    // Verifier processes the same statement, but with random input values
    let mut composer: StandardComposer = add_dummy_composer(7);
    let var_a = composer.add_input(Scalar::from(Scalar::zero()));
    let var_b = composer.add_input(Scalar::from(Scalar::zero()));
    composer.bool_gate(var_b); 
    composer.bool_gate(var_a);
            
    // Trim the SRS
    let (ck, vk) = public_parameters.trim(composer.circuit_size().next_power_of_two()).unwrap();
            
    // Create a new Evaluation Domain
    let domain = EvaluationDomain::new(composer.circuit_size()).unwrap();
    
    // Initialise transcript
    let mut transcript = Transcript::new(b"");
    
    // Preprocess circuit
    let preprocessed_circuit = composer.preprocess(&ck, &mut transcript, &domain);
    
    // Verify proof
    proof.verify(&preprocessed_circuit, &mut transcript, &vk, &public_inputs)
    
};
assert_eq!(ok, true);
```

## Documentation

WIP

## Performance

WIP

## Acknowledgements

- Reference implementation AztecProtocol/Barretenberg
- FFT Module and KZG10 Module were taken and modified from zexe/zcash and scipr-lab respectively.


## About

Implementation designed by the [dusk](https://dusk.network) team
