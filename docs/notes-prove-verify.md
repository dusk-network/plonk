This module contains the notes on 
how the prover algorithm is 
constructed for PLONK.

PLONK proof construction 
========================

Following on from the generic
SNARK construction, 
here we will give the set up
of a PLONK proof and show 
which steps need to be satisfied
to utilise the protocol.

First we will explain the 
derivation and simplification 
of the arithmetic circuits. 

PLONK uses both gate constraints 
and copy constraints, to collect 
like expressions. Using the same
example of:

\\[
\begin{aligned}
\mathbf{W}\_L 
\cdot 
\mathbf{W}\_R = 
\mathbf{W}\_O,
\end{aligned}
\\]

We can express multiples of the 
same wires in or out of the same 
gate, with the above equation.

Thus we have 'ith' gates, so the 
index from left or right across 
the circuit is mitigated for 
wires which are equal. 

For example, in the two equations:

\\[
\begin{aligned}
\mathbf{A}\_{1} 
\circ 
X 
\cdot 
\mathbf{B}\_{1} 
\circ 
X^2 
= \mathbf{C}\_{1}
\end{aligned}
\\]
and 
\\[
\begin{aligned}
\mathbf{A}\_{2} 
\circ 
X^2 
\cdot 
\mathbf{B}\_{2} 
\circ 
X 
= \mathbf{C}\_{2}
\end{aligned}
\\]

We can state the equalities that: 
\\[
\begin{aligned} 
\mathbf{A}\_{1} = \mathbf{B}\_{2} \\\\
&\\\\
\mathbf{B}\_{1} = \mathbf{A}\_{2} \\\\
\end{aligned}
\\]

These are examples of constraints 
collected in PLONK. Which is done
the same for addition gates, except
the gate constrain satisfies:

\\[
\begin{aligned}
\mathbf{W}\_L + \mathbf{W}\_R = \mathbf{W}\_O
\end{aligned}
\\]

PLONK also uses 'copy
constraints', which are used to 
associate wires, which have 
equality, from the entire circuit.
These constraints are checked 
with a permutation argument. 
In essence, this checks that 
wires are not repeated by using 
randomness given by the verifier. 

This process is better explained in 
within the permutation section of
the notes.

After the constraints
are made, they are formatted into a 
system of numerical equations, 
which in PLONK are reduced to a 
small amount of polynomial 
equations which are capable of 
representing the constraints.
PLONK allows us to combine the
two gate equations by describing 
their relationship relative to 
the role in the circuit.
PLONK also has constants, which
are denoted as 'Q'. These 
values will change for each 
programme. The shape of 
the circuit is defined by
these values. When they are 
combined with the gate 
equations, we get the 
polynomial equation for 
a reduced form as:

\\[
\\\\ \mathbf{L} = left 
\\\\ \mathbf{R} = right 
\\\\ \mathbf{O} = output 
\\\\ \mathbf{M} = multiplication 
\\\\ \mathbf{C} = constants 
\\]

\\[ 
\mathbf{Q}\_L \cdot \mathbb{a}\_i +
\mathbf{Q}\_R \cdot \mathbb{b}\_i +
\mathbf{Q}\_0 \cdot \mathbb{c}\_i +
\mathbf{Q}\_M \cdot \mathbb{a}\_i\mathbb{b}\_i +
\mathbf{Q}\_C = 0
\\]
This can be used for both
addition and multiplication
gates, where their values 
can be provided by the user 
depending on the circuit 
composition. 
For an addition gate, 
we derive it as follows:

\\[
\begin{aligned}
\mathbf{Q}\_L = 1, 
\mathbf{Q}\_R = 1, 
\mathbf{Q}\_0 = -1, 
\mathbf{Q}\_M = 0, 
\mathbf{Q}\_C = 1
\end{aligned}
\\]

Which results in:
\\[ 
\mathbb{a}\_{i} +
\mathbb{b}\_{i} -
\mathbb{c}\_{i} = 0
\\]

For a multiplication gate, 
we derive it as follows:

\\[
\begin{aligned}
\mathbf{Q}\_L = 0, 
\mathbf{Q}\_R = 0, 
\mathbf{Q}\_0 = -1, 
\mathbf{Q}\_M = 1, 
\mathbf{Q}\_C = 0
\end{aligned}
\\]


Which results in:
\\[ 
\mathbb{a}\_{i} 
\cdot
\mathbb{b}\_{i} -
\mathbb{c}\_{i} = 0
\\]

With this format, there is 
a specific method used to 
convert all the equations 
into polynomial form.
Basically, in order to
bundle
these together, PLONK can 
take sets of equations and 
turn them into one single 
equation over polynomials. 
This is called the evaluation 
form. We are then able to 
use Lagrangian interpolation
to convert to coefficient form. 
The only thing this interpolation 
is doing,
is allowing us to evaluate a
functions over specific points,
for 'x' values, where the target
polynomial is equal to '1' or 
'0'.

With these specific bases, we
can derive the relation between 
all sets of equations into one 
single polynomial equation,
where we have a vector of inputs
to each gate type:
\\[
\begin{aligned}
\mathbf{Q}\_L(x) \cdot a(x) +
\mathbf{Q}\_R(x) \cdot b(x) +
\mathbf{Q}\_0(x) \cdot c(x) +
\mathbf{Q}\_M(x) \cdot a(x)b(x) +
\mathbf{Q}\_C(x) =
0
\end{aligned}
\\]

The utility for this in PLONK, 
as a univeral SNARK, is that 
any operation or relationship 
that holds with the inputted 
vectors, will also hold over 
the polynomial.

In order to check this in PLONK, 
a 'vanishing polynomial' is 
introduced. Which is just a 
polynomial equal to zero for
all the points we evaluate at.
So this means that the vectors
will be divisible by this vanishing
polynomial, if the expression we 
check does indeed hold. 

To summarise what the PLONK
proof must satisfy:

The generation of copy and 
gate constraints where the 
former are representative 
of permuted wires. Generate 
all of the polynomials to  
be checked against the 
vanishing polynomials.
Take all of the wire values
and convert them into three
polynomials, \\({\mathbf A}(z)\\), 
\\({\mathbf B}(z)\\), 
\\({\mathbf C}(z)\\). 
Check the polynomials at 
some random \\({\mathbf Z\_z}\\), by making
commitments and checking 
the evaluation form. 
Then commit all evalution 
polynomials forms for the 
verfier. 









Lagrangian polynomials
======================

The use of polynomials in the 
PLONK proving scheme refers
to specific evaluation domains,
named Lagrangian polynomials,  
based on interpolation of two 
functions of particular group
elements. The following section 
gives a more comprehensive
understanding to the way in 
which these polynomials are 
formed, given certain inputs. 


Langrangian polynomials are 
introduced as a means of 
constructing continous 
functions
from discrete data. With alternative 
polynomial constructions, discrete 
data sets can be approximated; 
Langrangian polynomials, 
however, 
form a solution that fits data exactly.
This is achieved through *interpolation*, 
which finds a linear combination of 'n' 
inputted functions with respect to a 
given data set which imposes 'n' 
constraints and computes 
an exact fitting solution. 

Linear Algebra dictates that the interpolation polynomial ought 
to be formed from the system \\({\mathbf A}(x)\\) = 
\\({\mathbf b}\\), 
where \\({\mathbf b}\_i\\) = 
\\({\mathbf y}\_i\\), i = 0,...,n 
and the entries of 
\\({\mathbf A}(x)\\)
are defined by \\({\mathbf a}\_{ij}\\) = 
\\({\mathbf P}(x\_{i})\\),
and \\(i,j \in 0,....,n,\\) 
Additionally, the used points for the 
interpolation are 
\\(x\_{0},x\_{1}...,x\_{n}\\), 
from which the data points
\\(y\_{0},y\_{1}...,y\_{n}\\), are obtained, 
and 
\\({\mathbf P}\_j(x\_i) = x^{j}\\). 
Where \\(i \in 0,1,...,n\\). The basis 
\\(1,x,...,x^{n}\\)
of the space of polynomials, degree n+1 is called the *monomial 
basis*, and the corresponding matrix A is called the *Vandermode
matrix* for the points \\(x\_{0},x\_{1}...,x\_{n}\\). 

*Langrangian interpolation*, however, has the matrix A, as the identity 
matrix. 
This stems from writing the interpolating polynomial as:

\\[
\begin{aligned}
\mathbf{p}\_n(x) = \sum_{j=0}^{n} y_i\mathbb{L}\_n,j(x)
\end{aligned}
\\]




 The polynomials \\({\mathbb L}\_n\\) and  
 \\(j(x)\\) = 0,...,n are interpolations
 of the points \\(x\_{0},x\_{1}...,x\_{n}\\). They are commonly called the 
*Lagrangian polynomials*.
They are wriiten in the form:

\\[
\begin{aligned}
\mathbb{L}\_n,j(x) = 
\prod_{m=0}^{k} 
\frac{(x-x\_{m})}
{(x\_{j}-x\_{m})}
\end{aligned}
\\]

 the unique solution polynomial of degree 'n' that satisfies this 
\\[
\begin{aligned}
\mathbf{P}\_n(x\_j)
\end{aligned}
\\]

where
\\[
\begin{aligned}
i,j = \mathbb{f}(x\_j), \mathbb{j} = 0,1,...1,n
\end{aligned}
\\]

 This polynomial, \\({\mathbf P}\_n(x\_j)\\) 
 is called the *interpolating
 polynomial* of \\(\mathbb{f}(x)\\). 

 To understand these as an expanded product argument, it can be written as

 Given a set of k + 1 data points

[data points](https://wikimedia.org/api/rest_v1/media/math/render/svg/5e4f064b4751bb32d87cc829aca1b2b2f38d4a6d)

where no two  
[x_j](https://wikimedia.org/api/rest_v1/media/math/render/svg/5db47cb3d2f9496205a17a6856c91c1d3d363ccd) are the same, 
the interpolation polynomial in the Lagrange form is a linear combination

[Lagrange polynomial](https://wikimedia.org/api/rest_v1/media/math/render/svg/d07f3378ff7718c345e5d3d4a57d3053190226a0)

of Lagrange basis polynomials.
[Basis Polynomial](https://wikimedia.org/api/rest_v1/media/math/render/svg/6e2c3a2ab16a8723c0446de6a30da839198fb04b)
 
 
