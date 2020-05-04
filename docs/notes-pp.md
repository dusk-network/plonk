The notes within this module explain the inner workings
of the permutation polynomial evaluations.


Permutation polynomials
======================

A permutation polynomial is bijective 
function which describes a permutation, 
of a group of elements. These functions 
are commonly denoted as polynomial 
functions when the elements they 
contain, as well as the mapping itself,
is over a finite field. 

The purpose of constructing these 
polynomials is often for analysis,
which is done on a permutated set. 
A permutated set is a different 
linear arrangement of elements. 

The linearity of these is how 
permuatations differ from other 
means of selection from a set. 

For example: 

\begin{aligned}
{1,2,3}
\end{aligned}

is a number set which can have 
only six permuatations, namely:

\begin{aligned}
{1,2,3}
{3,2,1}
{2,1,3}
{2,3,1}
{1,3,2}
{3,1,2}
\end{aligned}

This example satisifes the two 
main properties which define set
permuatations:

1. The number of permutations is at most 
n! for n elements. 

2. The permutation is a bijection onto
itself. 

These basic properties are used in 
the construction of zero knowledge 
proofs and when the inividual 
permutations are described, they 
are often compounded into 
polynomials which describe these many
functions as polynomials over sets.
