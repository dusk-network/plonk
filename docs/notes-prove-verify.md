In this module, the notes on how the prover 
algorithm and verification functions are constructed
for PLONK, are documented.

PLONK proof construction 
========================

Following on from the generic
SNARK construction, 
here we will give the set up
of a PLONK proof and show 
which steps need to be satisfied
as part of the protocol.

First we will explain the 
derivation and simplification 
of the arithmetic circuits. 

PLONK uses both gate constraints 
and copy constraints, to collect 
like expressions. Using the same
example of:

\\[
\mathbf{W}\_*L* \cdot \mathbf{W}\_*R* = \mathbf{W}\_*O*,
\\]

We can express multiples of the 
same wires in or out of the same 
gate, with the above equation.
PLONK also uses 'copy
constraints', which are used to 
associate wires, which have 
equality, from the entire circuit.

Thus we have 'ith' gates, so the 
index from left or right across 
the circuit is mitigated for 
wires which are equal. 

For example, in the two equations:

\\[
\begin{aligned}
\mathbf{A}\_*1* \circ X \cdot \mathbf{B}\_*1* \circ \X^{2} 
= \mathbf{C}\_*1*\\\\
and 
\mathbf{A}\_*2* \circ X^{2} \cdot \mathbf{B}\_*2* \circ \X 
= \mathbf{C}\_*2*\\\\
\end{aligned}
\\]

We can state the equalities that: 
\\[
\begin{aligned} 
\mathbf{A}\_*1* = \mathbf{B}\_*2* \\\\
&\\\\
\mathbf{B}\_*1* = \mathbf{A}\_*2* \\\\
\end{aligned}
\\]

These are examples of constraints 
collected in PLONK. Which is done
the same for addition gates, except
the gate constrain satisfies:

\\[
\mathbf{W}\_*L* + \mathbf{W}\_*R* = \mathbf{W}\_*O*,
\\]

After the constriants
are made, they are formatted into a 
system of mumerical equations, 
which in PLONK are reduced to a 
small amount of polynomial 
equations which are capable of 
representing the two types.
PLONK allows us to combine the
two gate equations by describing 
their relationship relative to 
the role in the circuit.
PLONK also has constant, which
are denoted as 'Q'. These 
values will change for each 
programme. When they are 
combined with the gate 
equations, we get the 
polynomial equation for 
a reduced form as:

\\[
\begin{aligned}  
*L* = left \\\\
*R* = right \\\\
*O* = output \\\\
*M* = multiplication \\\\ 
*C* = constants \\\\

\mathbf{Q}\_*L\_i* \circ a\_i +
\mathbf{Q}\_*R\_i* \circ b\_i +
\mathbf{Q}\_*0\_i* \circ c\_i +
\mathbf{Q}\_*M\_i* \circ a\_ib\_i +
\mathbf{Q}\_*C\_i* =
0
\end{aligned}
\\]
This can be used for both
addition and multiplication
gates, where there values 
can be provided by the user 
depending on the circuit 
composition. 
For an addition gate, 
we derive it as follows:

\\[
\begin{aligned}
\mathbf{Q}\_*L\_i* = 1
\mathbf{Q}\_*R\_i* = 1
\mathbf{Q}\_*0\_i* = -1
\mathbf{Q}\_*M\_i* = 0
\mathbf{Q}\_*C\_i* = 1
\end{aligned}
\\]

Which results in:
\\[
\begin{aligned}  
a\_i +
b\_i -
c\_i =
0
\end{aligned}
\\]

For a multiplication gate, 
we derive it as follows:

\\[
\begin{aligned}
\mathbf{Q}\_*L\_i* = 0
\mathbf{Q}\_*R\_i* = 0
\mathbf{Q}\_*0\_i* = -1
\mathbf{Q}\_*M\_i* = 1
\mathbf{Q}\_*C\_i* = 0
\end{aligned}
\\]

Which results in:
\\[
\begin{aligned}  
a\_ib\_i -
c\_i =
0
\end{aligned}
\\]

With this format, there is 
a prover who has a 






The use of polynomials in the 
PLONK proving scheme refers
to specific evaluation domains,
names Lagrangian polynomials,  
based on interpolation of two 
functions of a particular group
elements. The following section 
gives a more comprehensive
understanding to the way in 
which these polynomials are 
formed, given certain inputs. 


Langrangian polynomials are 
introduced as a means of 
constructing continous functions
from discrete data. With alternative 
polynomial constructions, discrete 
data sets can be approximated; 
Langrangian polynomials, however, 
form a solution that fits data exactly.
This is achieved through *interpolation*, 
which finds a linear combination of 'n' 
inputted functions with respect to a 
given data set which imposes 'n' 
constraints and computes 
an exact fitting solution. 

Linear Algebra dictates that interpolation polynomial ought 
to be formed from the system {\mathbf{A}\{x}} = {\mathbf{b}}, 
where b\_i = y\_i, i\\ = 0,...,n\\, and the entries of {\mathbf{A}} 
are defined by {\mathbf{a}}\_{\operatorname{ij}} = 
{\mathbf{p}}{(x\_i)},i\\,j\\ = 0,....,n, where x\_0,x\_1,...,x\_n 
are the points at which data y\_o, y\_1,...,y\_n are obtained, and 
{\mathbf{p\_j}}{(x\_i)} = x^{j}, j\\ = 0,1,...,n. The basis {1,x\\,...,
x^{n}} of the space of polynomials degree n\\+1 is valled the *monomial 
basis*, and the corresponding matrix A is called the *Vandermode
matrix* for the points x\_0, x\_1,...,x\_n. 

*Langrangian interpolation*, however, has the matrix A, as the identity 
matrix. 
This stems from writing the interpolating polynomial as

\begin{aligned}
 {\mathbf{p\_n }}{(x\\)} = \sum_{j=0}^{n} y\_i\mathcal{L}\_n,j{(x)},
 \end{aligned}

where the polynomials {\mathcal{L\_n},\_j(x\_i)} have the property 
that 
\begin{aligned}
  {\mathcal{L\_n},\_j(x\_i)}
    \begin{cases}
      1 & \text{if $i$ = $j$}\\
      0 & \text{if $i$ \neq $j$}\\

       
\end{aligned}

 
 The polynomials {\mathcal{L\_n},\_j}, j\\ = 0,...,n, are intertpolations
 of the points x\_0, x\_1,...,x\_n. Theya are commonly called the 
*Lagrangian polynomials*.
They are wriiten in the form 
\begin{aligned}
 {\mathcal{L_{n,j}(x) = \prod_{k=0 k\neqj}^{n} frac{(x-x_{k}){(x_{j}-x_{k})
 \end{aligned}

 the unique solution polynomial of degree 'n' that satisfies this 
\begin{aligned}
 {\mathbf{p\_n}}{(x\_j)},i\\,j\\ = $f$(x\_j), $j$ = 0,1,...1,n.
 \end{aligned}

 This polynomial, {\mathbf{p\_n}}{(x\_j)} is called the *interpolating
 polynomial* of $f$(x). 

 To understand these as an expanded product argument, it can be written as

 Given a set of k + 1 data points

[data points](https://wikimedia.org/api/rest_v1/media/math/render/svg/5e4f064b4751bb32d87cc829aca1b2b2f38d4a6d)

where no two  
[x_j](https://wikimedia.org/api/rest_v1/media/math/render/svg/5db47cb3d2f9496205a17a6856c91c1d3d363ccd) are the same, 
the interpolation polynomial in the Lagrange form is a linear combination

[Lagrange polynomial](https://wikimedia.org/api/rest_v1/media/math/render/svg/d07f3378ff7718c345e5d3d4a57d3053190226a0)

of Lagrange basis polynomials
[Basis Polynomial](https://wikimedia.org/api/rest_v1/media/math/render/svg/6e2c3a2ab16a8723c0446de6a30da839198fb04b)
 
 
 Example
 ======= 
 To find the unique *Lagranian interpolation* of polynomial p\_3(x),
 with degree \leq 3, from the following set of data points:
 \documentclass{article}


\begin{table}
  \begin{center}
    \label{Data points}
    \begin{tabular}{l|c|r} % <-- Alignments: 1st column left, 2nd middle and 3rd right, with vertical lines in between
      \textbf{Value 1} & \textbf{Value 2} & \textbf{Value 3}\\
      $i$ & $x\_i$ & $y\_i$ \\
      \hline
      0 & -1 & 3\\
      1 & 0 & -4\\
      2 & 1 & 5\\
      3 & 2 & -6
    \end{tabular}
  \end{center}
\end{table}

In order to find this polynomial, we must construct the Lagrangian 
of the form
{\mathcal{L_{n,j}(x) = \prod_{i=0 i\neqj}^{n} frac{(x-x_{j}){(x_{j}-x_{i})

Calculated as follows:

$\mathcal{L}_{3,0}(x) = \frac{(x-x_{1})(x-x_{2})(x-x_{3})}{(x_{0}-x_{1})(x_{0}-x_{2})(x_{0}-x_{3})} = 
\frac{(x-0)(x-1)(x-2)}{(-1-0)(-1-1)(-1-2)} = \frac{x(x^{2}-3x+2)}{(-1)(-2)(-3)} = -\frac{1}{6}(x^{3}-3x^{2}+2x)$

$\mathcal{L}_{3,1}(x) = \frac{(x-x_{0})(x-x_{2})(x-x_{3})}{(x_{1}-x_{0})(x_{1}-x_{2})(x_{1}-x_{3})} = 
\frac{(x+1)(x-1)(x-2)}{(0+1)(0-1)(0-2)} = \frac{(x^2-1)(x-2)}{(1)(-1)(-2)} = \frac{1}{2}(x^{3}-2x^{2}-x+2)$ 

$\mathcal{L}_{3,2}(x) = \frac{(x-x_{0})(x-x_{1})(x-x_{3})}{(x_{2}-x_{0})(x_{2}-x_{1})(x_{2}-x_{3})} = 
\frac{(x+1)(x-0)(x-2)}{(1+1)(1-0)(1-2)} = \frac{x(x^2-x-2)}{(2)(1)(-1)} = -\frac{1}{2}(x^{3}-x^{2}-2x)$ 

$\mathcal{L}_{3,3}(x) = \frac{(x-x_{0})(x-x_{1})(x-x_{2})}{(x_{3}-x_{0})(x_{3}-x_{1})(x_{3}-x_{2})} = 
\frac{(x+1)(x-0)(x-1)}{(2+1)(2-0)(2-1)} = \frac{x(x^2-1)}{(3)(2)(1)} = \frac{1}{6}(x^{3}-x)$ 


This provides the unique polynomial which fits the given data sets, 
given by the interpolating polynomial

$p_{3}(x) = \sum_{j=0}^{3}y_{j}\mathcal{L}_{3,j}(x) = y_{0}\mathcal{L}_{3,0}(x) + y_{1}\mathcal{L}_{3,1}(x) + y_{2}\mathcal{L}_{3,2}(x) + y_{3}\mathcal{L}_{3,3}(x) = 
(3)(-\frac{1}{6})(x^{3}-3x^{2}+2x) + (-4)\frac{1}{2}(x^{3}-2x^{2}-x+2) + (5)(-\frac{1}{2})(x^{3}-x^{2}-2x) + (-6)\frac{1}{6}(x^{3}-x) = 
(-\frac{1}{2})(x^{3}-3x^{2}+2x) + (-2)(x^{3}-2x^{2}-x+2) + (-\frac{5}{2})(x^{3}-x^{2}-2x) - (x^{3}-x) = 
(-\frac{1}{2}-2-\frac{5}{2}-1)x^{3} + (\frac{3}{2} + 4 + \frac{5}{2})x^{2} + (-1+2+5+1)x - 4 = 
-6x^{3}+8x^{2}+7x-4$

Lagrangian polynomials are verifiable; if each x_{i}, for i\\ \exist
0...n, is substituted into p_{n}(x), then we obtain p_{n}(x_{i}) = 
y_{i}.