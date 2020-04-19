This module contains the methodology of how
zk-SNARKS are constructed.

SNARK
=====
These notes will 
show an abstraction on the construction 
of SNARKs by showing the mathematical 
steps involved. 

Zk-SNARK stands for zero-knowledge 
Succinct Non-Interactive ARgument of
Knowledge. Implementing a SNARK 
protocol allows us to prove that a
presented statement is true without
revealing anything other then the 
statement itself. 

The type of SNARK we will focus on
will be one with a pre-processing 
stage. This means that the inputs 
to our SNARK system is an output
of a program. We will also show 
how SNARKs satisfy the fundamental
features of zero knowledge. Namely:
Completeness, Soundess and Zero 
Knowledge. 

To construct their proofs, SNARKS
convert an arithmetic circuit into
an algebraic expression of polynomials. 
The arithemtic circuit here, is  
a mapping, performed by a system of 
wires and gates, where the outputs 
are inputs which have passed through 
the circuit. 

For SNARK circuits, the prover will 
select gates, 
e.g. 

*Multiplication gates* represented 
with two input wires to the gate, 
and one product wire, such that:

\\[
\mathbf{W}\_*L* \cdot \mathbf{W}\_*R* = \mathbf{W}\_*O*,
\\]
Where:

* \\(\mathbf{W}\_*L*\\) is representative of the left input wire to the gate
* \\(\mathbf{W}\_*R*\\) is representative of the right input wire to the gate
* \\(\mathbf{W}\_*O*\\) is representative of the output wire of the gate

The variables rely upon another 
set of contraints when inside 
the circuit. These are the gate 
constants:


\\[
\mathbf{a}\_*L*, \mathbf{a}\_*R*, \mathbf{a}\_*O*,
\\]
Where:

* \\(\mathbf{a}\_*L*\\) is the left input to the gate 
* \\(\mathbf{a}\_*R*\\) is the right input to the gate
* \\(\mathbf{a}\_*O*\\) is the output of the gate

The wires values can be seen as 
the weights to each of the inputs.

Constrained as:

\\[
\mathbf{W}\_*L* \cdot \mathbf{a}\_*L* +
\mathbf{W}\_*R* \cdot \mathbf{a}\_*R* +
\mathbf{W}\_*O* \cdot \mathbf{a}\_*O* =
0
\\]

When a program is chosen, the operations 
are expressed in terms of circuits like
the one above. 

Many programmes and their computations
have a large range of operations,
so the number of these gates they 
need to construct can be very 
large. Therefore, we use a 
technique called a 'Quadratic 
Arithmetic Programme' (QAP)
, to bundle the constraints
together. For example, 
many wires may be of the same
value and rather than 
computing them differently 
for each programme, they can 
be collected together and 
the constraint can be 
checked at varying values. 
This was, a proof can just 
check for values at certain 
indices. Following this, the 
indices the values are being
checked at are not numbers, 
but are instead polynomials.
This QAP is intended to give 
the prover the necessary 'tools'
to construct a proof from a 
given arithmetic circuit.  

Following on from the example
above, we can show a QAP being
constructed from an 'n' number 
of multiplication gates. The 
inputs to the gates will be 
a vector of polynomials, all 
evaluated for indice value at
some polynomial Z\_{(*z*)}

Let the left input polynomial be: 

\\[
\begin{aligned}
\vec{A} = (A\_{i}(z))\_{i=0}^{n}\\\\
\end{aligned}
\\]

Let the right input polynomial be: 

\\\[
\begin{aligned}
\vec{B} = (B\_{i}(z))\_{i=0}^{n}\\\\ 
\end{aligned}
\\]

Let the outputs polynomial be: 

\\[
\begin{aligned}
\vec{C} = (C\_{i}(z))\_{i=0}^{n}\\\\ 
\end{aligned}
\\]

The coefficients of these
polynomials are inside 
some [finite field][finite_field]
, which also contains the 
polynomial Z\_{(*z*)}.
As a result, it can be checked
that the Z\_{(*z*)} divides
the mul gate polynomials. 

This is done in the following 
way:

P(z) = A(z)*B(z) - C(z)

When given the above equation, 
the verifier can check the 
divisibility of P(z) by 
Z\_{(*z*)}.





[finite_field]: https://web.stanford.edu/class/ee392d/Chap7.pdf












