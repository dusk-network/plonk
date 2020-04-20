In this module, the notes on how the prover 
algorithm and verification functions are constructed
for PLONK, are documented.

PLONK proof construction 
========================

Following on from the generic
SNARK construction, given in
[Proof construction components](snark_construction/index.html), 
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
PLONK also has constants 
in gate equations

