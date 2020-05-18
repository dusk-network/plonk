Contained within this module are the notes on 
how the permutation argument is formed.


Permutation argument
==============

Within PLONK, the permutation 
polynomials are used to compare 
arguments about the proving 
scheme.  

These arguments are 
checking that wire values, 
within the circuit, are
being correctly copied. 
As is noted in other parts
of the docs, there is the 
need for a copy check in 
in SNARK schemes. This is 
crucial in our zk-SNARK
scheme, to ensure the 
correctness of wires when 
bundling similar wires 
together.



The properties of a permutation 
polynomial are used in this proving 
scheme, as PLONK checks the 
correctness of a shuffle in 
its proving algorithm, by 
comparing the permutations 
of polynomials to the originals.
This is essentially showing 
that the products of polynomials
are the same, despite the ordering 
being constructed differently.
In principle, PLONK can compare sets 
of polynomials for equality by 
comparing `n` number of polynomials 
with the same `n` number of polynomials 
, where the elements have been 
shuffled. 


Given a set of  values, at a 
particular position, we can create 
a mapping for the initial index into a 
new position, with a permutation. 

To understand how these polynomials
work in stand alone setting, we 
give the below example. 


Given initial values, 
1,2,3,4,5 each occupying 
their respective positions
A,B,C,D,E

\begin{aligned}

// +-----+-----+-----+-----+-----+
// |  A  |  B  |  C  |  D  |  E  |
// +-----+-----+-----+-----+-----+
// |  1  |  2  |  3  |  4  |  5  |
// +-----+-----+-----+-----+-----+

\end{aligned}

If we then have a mapping of:

\begin{aligned}

\\[
\mathbf{a}(1) = 5
\mathbf{a}(2) = 2
\mathbf{a}(3) = 3
\mathbf{a}(4) = 1
\mathbf{a}(5) = 4
\\]

\end{aligned}

Which gives a second, permutuated row, 
of:

\begin{aligned}

// +-----+-----+-----+-----+-----+
// |  A  |  B  |  C  |  D  |  E  |
// +-----+-----+-----+-----+-----+
// |  1  |  2  |  3  |  4  |  5  |
// +-----+-----+-----+-----+-----+
// |  3  |  5  |  1  |  4  |  2  |
// +-----+-----+-----+-----+-----+

\end{aligned}

We can form equations of polynomials 
to compare the values at each 
indice. As it possible to falsify
proofs, by having the sum of the 
equation arguments equal - without 
having the identities between the
monomials hold - therefore, two random 
challenges are introduced to the 
equation. 

The first is Beta, which is mutiplied
by the index and the second is 
gamma. Both of which, are taken from 
the prime field. 

To isolate the terms, for better evaluation
of the permutation, we are also capable 
of describing each indice as a type.
For this example, we will say 
values in column A & B = type 1\\, 
columms C & D = type 2\\
and column E = type 3.


Formulating this as an expression of 
the unpermutated polynomials, is as 
follows:

\begin{aligned}
\\[
    Z\_1\\\\ 
    =\\\\ 
(1\\+ 1*\beta +\gamma)
(1\\+ 2*\beta +\gamma)
(2\\+ 3*\beta +\gamma)
(2\\+ 4*\beta +\gamma)
(3\\+ 5*\beta +\gamma)
\\]

\end{aligned}

The permutated polynomials 
then become:

\begin{aligned}
\\[
    Z\_2\\\\ 
    =\\\\ 
(2\\+ 3*\beta +\gamma)
(3\\+ 5*\beta +\gamma)
(1\\+ 1*\beta +\gamma)
(2\\+ 4*\beta +\gamma)
(1\\+ 2*\beta +\gamma)
\\]

\end{aligned}

So now we have Z\_1,2\\, in the 
form of:

\begin{aligned}

\\[ 
    Z\_{i} = w\_{i} + \beta\_{i} + \gamma
\\]

\end{aligned}

To check this permutation, 
we are able to simply
divide the polynomial by 
its shuffled counterpart.
The principle of checking 
the division between these 
two Z\\ polynomials for an 
evaluation of `1`, is enough 
to determine the equality, 
or lack of, between them.