This module contains the methodology of how
zk-SNARKS are constructed.

SNARKs
=====
These notes will 
show an abstraction on the construction 
of SNARKs by showing the mathematical 
steps involved. 

ZK-SNARK stands for Zero-Knowledge 
Succinct Non-Interactive ARgument of
Knowledge. Implementing a SNARK 
protocol allows us to prove that a
presented statement is true without
revealing anything other than the 
statement itself. 

The type of SNARK we will focus on
will be one with a pre-processing 
stage. This means that the inputs 
to our SNARK system is an output
of a program. We will also show 
how SNARKs satisfy the fundamental
properties of zero knowledge. Namely:
Completeness, Soundess and Zero 
Knowledge. Completeness is the
verifier convinced that the claims
from the prover are true. Soundess
means that if the information is 
false, then the prover cannot 
convince the verifier otherwise.
Zero knowledge means that the 
proof should reveal nothing 
other than the statement or 
claim itself.

To construct their proofs, SNARKS
convert an arithmetic circuit into
an algebraic expression of polynomials. 
The arithemtic circuit here, is a mapping,
performed by a system of 
wires and gates, where the outputs 
are inputs which have passed through 
the circuit. The input for this is 
standardly assumed to be a computer 
program and those used in the zero 
knowledge fields tend to have a large
number of operations.

For SNARK circuits, the prover will 
select gates, 
e.g. 

*Multiplication gates* are represented 
with two input wires to the gate, 
and one product wire, such that:


\\({\mathbb W\_{L}}\\) \\(\cdot\\) \\({\mathbb W\_{R}}\\) = \\({\mathbb W\_{O}}\\),

Where:

* \\({\mathbb W\_{L}}\\) is representative of the left input wire to the gate\
* \\({\mathbb W\_{R}}\\) is representative of the right input wire to the gate
* \\({\mathbb W\_{O}}\\) is representative of the output wire of the gate

The variables rely upon another 
set of contraints when inside 
the circuit. These are the gate 
constants: \\({\mathbb a\_{L}}\\), \\({\mathbb a\_{R}}\\), \\({\mathbb a\_{O}}\\),

Where:

* \\({\mathbb a\_{L}}\\) is the left input to the gate 
* \\({\mathbb a\_{R}}\\) is the right input to the gate
* \\({\mathbb a\_{O}}\\) is the output of the gate

The wires values can be seen as 
the weights to each of the inputs.

They are constrained as:

\\[
\begin{aligned}
\mathbf{{W}}\_{L} \cdot \mathbf{a}\_{L} +
\mathbf{{W}}\_{R} \cdot \mathbf{a}\_{R}  -
\mathbf{{W}}\_{O} \cdot \mathbf{a}\_{O}  =
0
\end{aligned}
\\]

When a program is chosen, the operations 
are expressed in terms of circuits, like
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
This step involves checks for
the values at specified 
indices. Additionally, the 
indice values that are being
checked at are not numbers, 
but are instead polynomials.
This polynomial is computed 
by the QAP from the input 
vectors. This QAP is intended 
to give the prover the necessary
'tools' to derive these polynomials
for a proof, from a given
arithmetic circuit.  

Following on from the example
above, we can show a QAP being
constructed from an 'n' number 
of multiplication gates. The 
inputs to the gates will be 
a vector of polynomials, all 
evaluated for indice value at
some polynomial of their reduced
form, \\({\mathbf Z\_p}\\),

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
polynomial \\({\mathbf Z\_z}\\).
As a result, it can be checked
that the \\({\mathbf Z\_z}\\) divides
the multiplication gates
polynomial.


This is done by first constructing the full polynomial:

\\[
\begin{aligned}
\mathbf{P}(z) = 
\mathbf{A}(z) * 
\mathbf{B}(z) - 
\mathbf{C}(z)
\end{aligned}
\\]
When the above equation is 
constructed by the prover,
the verifier can check claims
by checking the divisibility 
of \\({\mathbf P}(z)\\) by
 \\({\mathbf Z\_z}\\). This 
\\({\mathbf Z\_z}\\) polynomial is 
often referred to as the 
'target polynomial'. The 
added benefit of having this
checked in polynomial form, 
is that even with a large 
polynomials, the identity
between the two will hold 
at most points if the identity
holds between the polynomials. 
Which means the check can between 
the two can be performed at
randomly chosen points to 
verify the proof.

In order to turn a given QAP
into a zk-SNARK, a prover must 
rely upon a third party. Which 
is more commonly known as 'a 
trusted set up'. The trusted
set up constructs the polynomial
\\({\mathbf Z\_z}\\). The prover then 
commits the vector values along 
with their secret input, known as 
the *witness*, to the equation
\\({\mathbf P}(z)\\) = 
\\({\mathbf A}(z)\\) *
\\({\mathbf B}(z)\\) - 
\\({\mathbf C}(z)\\)

Then the prover completes the 
divisibility check between P(z)
and \\({\mathbf Z\_z}\\). This way, the
verifier can be sure that the 
prover knows the *witness* value. 

The inner workings of the SNARK
also contain a 'bilinear pairing', 
which is referring to the fields 
which are used throughout the 
protocol. However, in detail 
explanations of these are a out 
of scope for these docs, more 
information on the role pairing
cryptography has within SNARK 
construction can be found [here][pairings]. 










[finite_field]: https://web.stanford.edu/class/ee392d/Chap7.pdf
[pairings]:https://eprint.iacr.org/2016/260.pdf











