Contained within this module are the notes on 
how the permutation argument is formed.


Permutation argument
==============

Within PLONK, the permutation 
polynomials are used to form 
arugments about the proving 
scheme. 

These arguments are used to 
check samples of elements, 
against the original ones. 
As is noted in other parts
of the docs, there is the 
need for a copy check in 
in SNARK schemes. This is 
crucial in our zk-SNARK
scheme, to ensure the 
correctness of wires and 
allow us to express circuits
with less differing vectors 
per polynomial. 

PLONK uses an argument to check 
the correctness of a shuffle in 
its proving algorithm. This allows 
for the checking of individual 
wires rather than entire sets. 
In principle, PLONK can compare sets 
of polynomials for equality by 
comparing an `n` degree polynomial 
with the same `n` degree polynomial 
where some elements have been 
rotated. 

Given a set of wire values, at a 
particular position, we can create 
a mapping for these wires into a 
new position with a permuatation. 

For example: 
Given initial wire values, 
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
to compare the wire values at each 
position. As it possible to falsify
proofs, by having the sum of the 
equation arguments equal - without 
having the identities between the
monomials hold - therefore, two random 
constants are introduced to the 
equation. 

The first is Beta, which is mutiplied
by the wire index and the second is 
gamma, which is derived from the prime 
field. 

To isolate the terms, for better evaluation,
we are also capable of describing each wire
as a type. For this example, we will say 
wires A & B = type 1\\, wires C & D = type 2\\
and wire E = type 3.


Formulating this an expression of the 
unpermutated polynomials, is as 
follows:

\begin{aligned}
\\[
    Z\_1\\\\ 
    =\\\\ 
(1\\+   \beta +\gamma)
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
(1\\+   \beta +\gamma)
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
divide a rotated syntax of 
the products by one another. 
The requirement for this 
rotation stems from the 
evaluation domain used in 
PLONK. Even still, the 
priniciple of checking the 
division between these two 
Z\\ polynomials for a `0`
value is enough to determine 
the equality, or lack of, 
between them.