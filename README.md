# PLONK (zexe backend branch)

**Warning: WIP**
This code is highly experimental, use at your own risk.
** This repository contains an implementation of PLONK. 
This is a pure rust implementation designed by the [dusk](https://dusk.network) team ** 

## PLONK
PLONK is a universal and updateable zk-SNARK proving scheme. First 
introduced in August by Ariel Gabizon, Zac Williamson and Oana Ciobotaru; 
this proof scheme requires a trusted set but one which has an updateable 
set up, which is proved only once for the entire sheme. The main advantage 
for this is that multiple parties can participate and there is a 
requirement that only one is honest. Additionally, the updateable feature 
means that more parties can be added later - this multi party set up 
leads to a consecutive participation. 

PLONK relies upon one single polynomial commitment and these are 'kate commitments'. 
Additionally, PLONK uses permutation arguments where the subgroup is evaluated. 

**This branch contains an implementation using [zexe](https://github.com/scipr-lab/zexe/tree/master/algebra) as backend for the elliptic curve 
operations as well as KZG10 as a backend for the polynomial commitment scheme.**

**If you're looking for fast prove times, you should use this branch atm since it has
multiscalar multiplication implemented for `BLS12_381` which allows faster polynomial
commitment operations.** 



## Acknowledgements
[Reference implementation AztecProtocol/Barretenberg](https://github.com/AztecProtocol/barretenberg)
[PLONK paper reference]()
