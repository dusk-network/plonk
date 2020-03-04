# PLONK, a zero knowledge proof scheme using the SNARK format

WIP

This code is highly experimental, use at your own risk.
Warning: WIP
** This repository will contain an implementation of PLONK. This is a pure rust implementation designed by the [dusk](https://dusk.network) team ** 

### PLONK
PLONK is a universal and updateable zk-SNARK proving scheme. First 
introduced in August by Ariel Gabizon, Zac Williamson and Oana Ciobotaru; 
this proof scheme requires a trusted set but one which has an updateable 
set up, which is proved only once for the entire sheme. The main advantage 
for this is that multiple parties can participate and there is a 
requirement that only one is honest. Additionally, the updateable feature 
means that more parties can be added later - this multi party set up 
leads to a consecutive participation. 

PLONK relies upon one single polynomial commitment and these are 'kate commitments'. Additionally, PLONK uses permutation arguments where the 
subgroup is evaluated. 

Roadmap 
- [x] Complete preselector polynomial calculation
- [x] Create composer for users
- [x] Build PSnark outputs
   - [x] PSnark output 1 
   - [x] PSnark output 2 
   - [x] PSnark output 3 
   - [x] PSnark output 4 
   - [x] PSnark output 5 
- [x] Build verification functions
- [x] Implement test vectors for equation checks
- [x] Derive test vectors for arguments
- [x] Build polynomials from all wire values and derive coefficients 
- [x] Generate randomness from Fiat Shamir using Merlin inputs
- [] Generate public inputs 
- [x] Evaluate the z polynomial at the root of unity 
- [x] Add prover logic
- [x] Add verifier logic
- [x] Implement travis auto document 

## Acknowledgements
Reference implementation AztecProtocol/Barretenberg
