In this module we show how and why the KZG10 
polynomial commitment scheme has been modularised 
for this PLONK implementation.

KZG10 Commitments 
==================

PLONK can be constructed with different 
commitment schemes and does not requre solely
homomorphic commitments. However, this library
has only homomorphic commitment schemes as they 
are intelligble for users and have many useful
properties.

We use 'KZG10 commitments', often called 'Kate' 
commitments refers to the commitments scheme 
created by Kate, Zaverucha and Goldberg. In 
cryptography, commitmment schemes allow for 
the use of otherwise impossible protocols, called z
ero knowledge proofs. These KZG10 allow us to have 
constant size proofs.
